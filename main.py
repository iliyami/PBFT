from secrets import token_bytes, randbelow
# from blspy import PrivateKey, AugSchemeMPL  # Commented out due to compatibility issues
import socket
import threading
import json
import time
import csv
import sqlite3
import os
import sys
import argparse
from client import PBFTClient
from shared import Shared
import hashlib

# Constants
INITIAL_BALANCE = 10
NUM_SERVERS = 7
NUM_CLIENTS = 10
F = (NUM_SERVERS - 1) // 3  # BPFT F
MAJORITY = 2*F + 1 #BPFT requires majority for prepare*, commit and checkpoint
threshold = F + 1

def generate_key_shares(secret, n, t):
    secret_key = randbelow(1000000)
    shares = [(secret_key + i) % 1000000 for i in range(n)]
    return shares

def sign_message(private_key_share, message):
    # Simple hash-based signature for compatibility
    message_str = str(message) + str(private_key_share)
    signature = hashlib.sha256(message_str.encode()).hexdigest()
    return signature

def combine_signatures(signatures):
    # Simple concatenation for compatibility
    combined_signature = "|".join(signatures)
    return combined_signature

def verify_signature(public_keys, combined_signature, message):
    # Simple verification for compatibility
    return True  # Always return True for now


# Sample server class handling TCP connections and PBFT protocol
class PbftServer:
    round_number = 0
    def __init__(self, server_id, port, peers, db_file, key_share):
        self.server_id = server_id
        self.port = port
        self.live_servers = []
        self.peers = peers
        self.pending_pbft = False
        self.balances = {key: 10 for key in range(1, NUM_CLIENTS + 1)}
        self.view = 1
        self.accepted_value = None
        self.accepted_number = None
        self.prepared = None
        self.message = None
        self.prepared_signatures = []
        self.transaction_queue = []
        self.total_transaction_time = 0  # Total time spent processing transactions
        self.total_transactions_committed = 0  # Count of committed transactions
        self.start_time = time.time() # Server start time (for transactions per second)
        self.majority_responses = 1
        self.majority_reached = False
        self.accept_majority_responses = 1
        self.accept_majority_reached = False
        self.response_lock = threading.Lock()
        self.accept_response_lock = threading.Lock()
        self.condition = threading.Condition(self.response_lock)  # Condition to wait for responses
        self.accept_condition = threading.Condition(self.accept_response_lock)  # Separate condition for accepted phase
        self.view_timeout = 8
        self.view_cancel_timeout = 3
        self.view_timer = None  # Timer for tracking the leader's response time
        self.vc_request_timer = None #Timer for tracking the view change request to cancel non-majority reached vc reqs
        self.view_change_pending = False
        self.vc_signatures = {}
        self.new_view_logs = []
        self.local_logs = []
        self.key_share = key_share
        self.public_key = None 

        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS transactions
                               (id INTEGER PRIMARY KEY,
                                sequence_number int,
                                sender TEXT,
                                receiver TEXT,
                                amount INTEGER,
                                view INTEGER,
                                status TEXT)''')
        self.conn.commit()


    def close(self):
        self.conn.close()

    def add_transaction_to_datastore(self, message, accepted_number, status):
        v, n = accepted_number
        new_curstor = self.conn.cursor()
        id, transaction = message
        sender, receiver, amount = transaction

        new_curstor.execute('''
            INSERT OR IGNORE INTO transactions (id, sequence_number, sender, receiver, amount, view, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (id, n, Shared.get_alphabet_for_number(sender), Shared.get_alphabet_for_number(receiver), amount, v, status))
            
        if new_curstor.rowcount > 0:
            self.conn.commit()
        new_curstor.close()
        # print(f"Server {self.server_id}: Transaction {block} added to persistent datastore (DB).")

    def replace_datastore(self, new_datastore):
        self.cursor.execute('DELETE FROM transactions')
        self.conn.commit()

        for transaction in new_datastore:
            id, sequence_number, sender, receiver, amount, ballot_number, process_id = transaction

            self.cursor.execute('''
                INSERT OR IGNORE INTO transactions (id, sequence_number, sender, receiver, amount, ballot_number, process_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (id, sequence_number, Shared.get_alphabet_for_number(sender), Shared.get_alphabet_for_number(receiver), amount, ballot_number, process_id))

        self.conn.commit()
        # print(f"Server {self.server_id}: Replaced the datastore with the new given datastore.")

    def get_all_transactions(self):
        new_cursor = self.conn.cursor()
        new_cursor.execute('SELECT * FROM transactions ORDER BY sequence_number ASC')
        transactions = new_cursor.fetchall()
        return transactions
        
    def get_transactions_by_status(self, status):
        new_cursor = self.conn.cursor()
        new_cursor.execute('''SELECT * FROM transactions
                       WHERE status = ?
                       ORDER BY sequence_number ASC''', (status,))
        transactions = new_cursor.fetchall()
        new_cursor.close()
        
        return transactions
    
    def get_transactions_by_seq(self, n):
        all = self.get_all_transactions()
        for trans in all:
            id, seq_num, s, r, amount, view, status = trans
            if n == seq_num:
                return status

        return 'X'
    
    def update_transaction_status(self, sequence_number, new_status):
        new_cursor = self.conn.cursor()
        
        new_cursor.execute("SELECT status FROM transactions WHERE sequence_number = ?", (sequence_number,))
        current_status = new_cursor.fetchone()
        
        if current_status:
            current_status = current_status[0]
            if current_status == 'E' and new_status in ['P', 'C']:
                new_cursor.close()
                return
        
        new_cursor.execute("UPDATE transactions SET status = ? WHERE sequence_number = ?", (new_status, sequence_number))
        self.conn.commit()
        new_cursor.close()


    def start_server(self, init):
        if init:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.bind_and_listen(server_socket)
            # Start a thread for accepting client connections
            threading.Thread(target=self.accept_connections, args=(server_socket,)).start()
        print(f"Server {self.server_id} started on port {self.port}")

    def bind_and_listen(self, server_socket):
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', self.port))
        server_socket.listen(5)

    def accept_connections(self, server_socket):
        while True:
            client_conn, _ = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_conn,)).start()

    def handle_client(self, conn):
        data = conn.recv(2048).decode()
        request = json.loads(data)
        if 'transaction' in request:
            self.handle_transaction(request)
        elif 'pbft' in request:
            self.handle_pbft_message(request['pbft'])
        elif 'command' in request:
            self.handle_commands(request['command'])
        elif 'request_type' in request and request['request_type'] == Shared.REQUEST_TYPE_BALANCE:
            threading.Thread(target=self.handle_balance_request, args=(request, conn)).start()

    def handle_balance_request(self, request, conn):
        """Handle read-only balance requests that bypass consensus"""
        if self.server_id in Shared.byzantines:
            print(f"Server {self.server_id}: Byzantine server - not responding to balance request")
            return
            
        client_info = request['client']
        balance_query = request['balance_query']
        client_to_query = balance_query['client_id']
        
        current_balance = self.calculate_balance(client_to_query)
        
        reply = {
            'balance_reply': {
                'client_id': client_to_query,
                'balance': current_balance,
                'server_id': self.server_id,
                'query_id': balance_query['query_id']
            }
        }
        
        try:
            client_port = client_to_query + 8000
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('localhost', client_port))
            client_socket.send(json.dumps(reply).encode())
            client_socket.close()
            
            log = f"Server {self.server_id}: Sent balance reply for client {Shared.get_alphabet_for_number(client_to_query)}: {current_balance}"
            self.local_logs.append(log)
        except Exception as e:
            print(f"Server {self.server_id}: Error sending balance reply: {e}")
        finally:
            conn.close()

    # ------------- PBFT Phases ----------------- #
    def handle_commands(self, command):
        command_type = command['type']
        if command_type == 'client_balance_request':
            self.client_balance_request(command)
        elif command_type == 'client_balance_response':
            self.client_balance_response(command)
        elif command_type == 'print_log':
            self.logs_dump()
        elif command_type == 'print_status':
            self.print_status_by_seq_num(command)
        elif command_type == 'print_db':
            self.db_dump()
        elif command_type == 'print_view':
            self.print_view()
        elif command_type == 'performance_request':
            self.performance_request()
        elif command_type == 'performance_response':
            self.performance_response()

    def handle_transaction(self, payload):
        client = payload['client']
        transaction = payload['transaction']
        self.live_servers = payload['live_servers']

        if self.view != self.server_id:
            self.view_timer = threading.Timer(self.view_timeout, self.view_change_request, args=('I', ))
            self.view_timer.start()

        if self.view != self.server_id:
            return

        if self.pending_pbft:
            new_request_timestamp = client['timestamp']
            for request in self.transaction_queue:
                queued_request_timestamp = request['client']['timestamp']
                if queued_request_timestamp == new_request_timestamp:
                    # print(f'return extra req={transaction}')
                    return
            
            self.transaction_queue.append(payload)
            # print(f"Server {self.server_id}: PBFT is in progress. Queuing transaction {transaction}.")
            return
        
        # print(f"Server {self.server_id}: Queuing transaction {transaction}.")
        # self.transaction_queue.put(transaction)
        seq_num, trans = transaction
        sender, receiver, amount = trans
        self.check_balance(sender)
        self.initiate_pbft(client, transaction)


    def handle_pbft_message(self, pbft_message):
        pbft_type = pbft_message['type']
        if pbft_type == 'view_change':
            self.handle_view_change(pbft_message)
        elif pbft_type == 'new_view':
            self.handle_new_view(pbft_message)
            
        if self.view_change_pending == False:
            if pbft_type == 'preprepare':
                self.handle_pre_prepare(pbft_message)
            elif pbft_type == 'prepare':
                self.handle_prepare(pbft_message)
            elif pbft_type == 'prepare_ack':
                self.handle_prepare_ack(pbft_message)
            elif pbft_type == 'commit':
                self.handle_commit(pbft_message)
            elif pbft_type == 'commit_ack':
                self.handle_commit_ack(pbft_message)
            elif pbft_type == 'catch_up_request':
                self.handle_catch_up_request(pbft_message)
            elif pbft_type == 'catch_up_response':
                self.handle_catch_up_response(pbft_message)

    def broadcast_message(self, message, include_self=False):
        live_ports = [server + 5000 for server in self.live_servers if server != self.server_id]
        if include_self:
            live_ports.append(self.server_id+5000)
        for peer_port in live_ports:
                self.send_message(peer_port, message) 

    def initiate_pbft(self, client, transaction):
        self.pending_pbft = True
        self.message = transaction
        self.prepared_signatures = []
        self.majority_responses = 1
        self.majority_reached = False
        self.accept_majority_responses = 1
        self.accept_majority_reached = False

        # Send PRE-PREPARE message to all peers
        n = PbftServer.assign_n(transaction)
        d = self.digest(transaction)
        self.view = self.server_id
        self.accepted_number = (self.server_id, n)
        self.accepted_value = d
        message = {'pbft': {
            'type': 'preprepare',
            'v': self.view,
            'n': n,
            'd': d,
            'm': transaction,
            'client': client,
            's': self.get_node_signature(self.server_id)
        }}
        self.add_transaction_to_datastore(self.message, self.accepted_number, 'PP')
        log = f'Broadcasting PP by leader:{self.server_id} for request {transaction}'
        self.local_logs.append(log)
        # print(log)
        self.broadcast_message(message)
        self.wait_for_majority()

    def view_change_request(self, dest):
        if self.view_timer == None:
            return
        self.view_change_pending = True
        self.vc_request_timer = threading.Timer(self.view_cancel_timeout, self.cancel_view_change)
        self.vc_request_timer.start()
        new_view = self.new_view()
        message = {'pbft': {
            'type': 'view_change',
            'v': new_view,
            # 'n': latest_checkpoint,
            # 'C': checkpoints,
            'i': self.server_id,
            's': self.get_node_signature(self.server_id)
        }}
        log = f'\nServer {self.server_id}: view change requested for v={new_view} from {dest}'
        self.local_logs.append(log)
        # print(log)
        self.broadcast_message(message, include_self=True)

    def handle_view_change(self, message):
        v = message['v']
        i = message['i']
        if self.server_id == v:
            self.vc_signatures[i] = message
            if len(self.vc_signatures) >= F + 1:
                message = {'pbft': {
                'type': 'new_view',
                'v': v,
                'v_signatures': self.vc_signatures.copy(),
                # 'O': self.O
                's': self.get_node_signature(self.server_id)
                }}
                self.new_view_logs.append(message)
                log = f'\nServer {self.server_id}: view change applied for v={v}'
                self.local_logs.append(log)
                # print(log)
                self.broadcast_message(message, include_self=True)

    def handle_new_view(self, message):
        if self.server_id in Shared.byzantines:
            return

        v = message['v']
        self.view = v
        self.vc_signatures = {}
        self.cancel_view_change()
        self.accepted_number = None
        self.accepted_value = None
        self.pending_pbft = False
        log = f'\nServer {self.server_id}: New view ={self.view} set!'
        self.local_logs.append(log)
        print(log)

    def reset_view_timer(self, dest):
        if self.view_timer == None:
            return
        self.vc_signatures = {}
        if self.vc_request_timer != None:
            self.vc_request_timer.cancel()
            self.vc_request_timer = None
        if self.view_timer != None:
            self.view_timer.cancel()
            self.view_timer = None
        self.view_timer = threading.Timer(self.view_timeout, self.view_change_request, (dest,))
        self.view_timer.start()
        # print(f'Server {self.server_id}: resetting from {dest} with thread {self.view_timer.name} ')

    def cancel_view_change(self):
        self.vc_signatures = {}
        self.view_change_pending = False
        if self.vc_request_timer != None:
            self.vc_request_timer.cancel()
            self.vc_request_timer = None
        if self.view_timer != None:
            self.view_timer.cancel()
            self.view_timer = None
        # print(f'\nServer {self.server_id}: cancelled!')

    def new_view(self):
        new_view = -1
        view = self.view
        while new_view == -1 or new_view not in self.live_servers:
            new_view = view+1%(NUM_SERVERS+1)
            if new_view == 0:
                new_view = 1
            view += 1
        return new_view
    
    def handle_pre_prepare(self, message):
        n = message['n']
        v = message['v']
        m = message['m']
        d = message['d']
        signature = message['s']
        

        # if self.accepted_number != None and self.accepted_number != (v, n):
        #     self.accepted_number = None
        #     self.accepted_value = None

        isValid = v == self.view and d == self.digest(m) and signature == self.get_node_signature(v) and (
            self.accepted_number == None or (self.accepted_number == (v, n) and self.accepted_value == d))

        if isValid:
            self.reset_view_timer('PP')

            partial_signature = self.generate_partial_signature(d)
            self.view = v
            self.accepted_number = (v, n)
            self.accepted_value = d
            self.message = m
             # Send PREPARE message to the collector (leader)
            leader_port = 5000+self.view
            message = {'pbft': {
            'type': 'prepare',
            'v': v,
            'n': n,
            'd': d,
            'i': self.server_id,
            's': self.get_node_signature(self.server_id),
            'partial_signature': partial_signature,
            'server_id': self.server_id
            }}

            self.add_transaction_to_datastore(self.message, self.accepted_number, 'PP')

            if self.server_id in Shared.byzantines:
                self.accepted_number = None
                self.accepted_value = None
                return
            
            log = f'server {self.server_id} acc num is {self.accepted_number} for n {n}'
            self.local_logs.append(log)
            # print(log)
            self.prepared_signatures.append(partial_signature)
            self.send_message(leader_port, message)
        else:
            log = f'server {self.server_id} PP was not valid!!!'
            self.local_logs.append(log)
            print(log)

    def handle_prepare(self, message):
        if self.server_id in Shared.byzantines:
            return
        
        n = message['n']
        signature = message['s']
        
        with self.response_lock:
            log = f'Receiving prepare by leader:{self.server_id} with payload: {message}'
            self.local_logs.append(log)
            # print(log)
            self.majority_responses += 1
            self.prepared_signatures.append(signature)
            if self.majority_responses >= MAJORITY:
                # Majority reached, send ACCEPT message
                start_time = time.time()
                while time.time() - start_time < 0.6:
                    self.response_lock.release()
                    time.sleep(0.1)  # Wait for 200ms to avoid busy-waiting
                    self.response_lock.acquire()
                self.majority_reached = True
                self.majority_responses = 1
                self.update_transaction_status(n, 'P')
                self.prepared_signatures.append(self.get_node_signature(self.server_id))
                self.condition.notify()

    def wait_for_majority(self, timeout=3):
        """Wait for majority of prepare responses or timeout"""
        with self.condition:
            # Wait until a majority is reached or the timeout occurs
            self.condition.wait_for(lambda: self.majority_reached, timeout=timeout)
            if self.majority_reached:
                # print(f"Server {self.server_id}: Majority of promises received, proceeding to send accept.")
                is_super_majority = self.majority_responses == 3*F+1
                self.majority_reached = False
                self.majority_responses = 1
                log = f'Majority reached! send prepare ack for {self.accepted_number}'
                self.local_logs.append(log)
                # print(log)
                if is_super_majority:
                    self.commit_transaction(True)
                else:
                    self.send_prepare_ack()
            else:
                log = f"Server {self.server_id}: Timeout reached on collecting prepares, aborting PBFT."
                self.local_logs.append(log)
                print(log)
                self.majority_reached = False 
                self.majority_responses = 1


    def send_prepare_ack(self):
        if self.accepted_number == None:
            return
        
        message = {'pbft': {
                'type': 'prepare_ack',
                'v': self.server_id,
                'n': self.accepted_number[1],
                'certificate': self.prepared_signatures,
            }}
        self.broadcast_message(message)
        self.wait_for_accepted_majority()


    def handle_prepare_ack(self, message):
        if self.server_id not in Shared.byzantines:
            self.reset_view_timer('Prepare Ack')

        signatures = message['certificate']
        v = message['v']
        n = message['n']

        isValid = len(signatures) >= MAJORITY and (self.accepted_number != None or self.accepted_number == (v, n))
        if isValid == False:
            return
        
        self.update_transaction_status(n, 'P')

         # Send Commit message to the collector (leader)
        leader_port = 5000+self.view
        message = {'pbft': {
            'type': 'commit',
            'v': self.view,
            'n': self.accepted_number[1],
            'd': self.accepted_value,
            'i': self.server_id,
            's': self.get_node_signature(self.server_id)
        }}
        self.prepared = (self.accepted_number[0], self.accepted_number[1], self.accepted_value)
        log = f"Server {self.server_id}: Sending commit request to the leader"
        self.local_logs.append(log)
        # print(log)
        self.send_message(leader_port, message)

    def wait_for_accepted_majority(self, timeout=3):
        """Wait for majority of accepted responses or timeout"""
        with self.accept_condition:
            # Wait until a majority of accepted messages is received or the timeout occurs
            self.accept_condition.wait_for(lambda: self.accept_majority_reached, timeout=timeout)
            if self.accept_majority_reached:
                # Commit the transaction after majority or timeout
                self.accept_majority_reached = False
                self.accept_majority_responses = 1
                log = f"Server {self.server_id}: Majority reached, commit and broadcast commit by leader with msg: {self.message} ."
                self.local_logs.append(log)
                # print(log)
                self.commit_transaction()
            else:
                log = f"Server {self.server_id}: Timeout reached for the commit majority!"
                self.local_logs.append(log)
                print(log)
                self.accept_majority_reached = False
                self.accept_majority_responses = 1


    def handle_commit(self, message):
        d = message['d']
        n = message['n']
        v = message['v']
        s = message['s']
        with self.accept_response_lock:
            if (v, n) != self.accepted_number or d != self.accepted_value:
                return
            
            self.accept_majority_responses += 1
            # print(f"Server {self.server_id}: Received commit request with s {s}")

            if self.accept_majority_responses >= MAJORITY:
                self.accept_majority_reached = True
                self.accept_condition.notify()
                # print(f"Server {self.server_id}: Reached majority, committing request {message}")

    def commit_transaction(self, is_super=False):
        # Commit the block locally
        start_time = time.time()
        self.update_transaction_status(self.accepted_number[1], 'C')
        # self.clear_outdated_logs(unique_major_block)

        # Update performance metrics
        processing_time = time.time() - start_time  # Calculate processing time
        self.total_transaction_time += processing_time
        self.total_transactions_committed += 1

        # Execution
        client_id = self.message[1][0]
        self.execute_transaction(client_id)

        # Broadcast COMMIT_ACK message to all other servers
        message = {
            'pbft': {
                'type': 'commit_ack',
                'v': self.view,
                'n': self.accepted_number[1],
                'd': self.digest(self.message),
                'i': self.server_id,
                's': self.get_node_signature(self.server_id),
                'sm': is_super
            }
        }
        self.broadcast_message(message)
        threading.Timer(0.2, self.handle_consensus_completion).start()

    def execute_transaction(self, client_id):
        transactions = self.get_all_transactions()
        commited = []
        executed = []
        for trans in transactions:
            id, n, s, r, amount, view, status = trans
            sender = Shared.get_number_for_alphabet(s)
            receiver = Shared.get_number_for_alphabet(r)
            normalized_trans = (id, n, sender, receiver, amount, view, status)
            if status == 'C':
                commited.append(normalized_trans)
            elif status == 'E':
                executed.append(normalized_trans)

        if len(commited) == 0:
            self.reply_client(client_id, 'yes')
            return

        for commit in commited:
            last_exec_n = 0 if len(executed) == 0 else executed[-1][1]
            id, n, sender, receiver, amount, view, status = commit
            if last_exec_n + 1 == n:
                log = f"Server {self.server_id}: Processed transaction n = {n} ({sender} -> {receiver}: {amount})"
                self.local_logs.append(log)
                # print(log)
                executed.append(commit)
                if self.balances[sender] - amount < 0:
                    self.update_transaction_status(n, 'E - Insufficient funds!')
                    self.reply_client(sender, 'no')
                else:
                    self.balances[sender] -= amount
                    self.balances[receiver] += amount
                    self.update_transaction_status(n, 'E')
                    self.reply_client(sender, 'yes')
            elif self.view != self.server_id:
                self.reset_view_timer('Else C')

    def reply_client(self, client_id, msg):
        self.cancel_view_change()
        self.send_message(client_id+8000, message = {'reply': msg, 'v': self.view})
        log = f"Server {self.server_id}: reply {msg} within view {self.view} for client:{client_id}"
        self.local_logs.append(log)
        # print(log)


    def handle_commit_ack(self, message):
        if self.server_id in Shared.byzantines:
            return
        
        self.reset_view_timer('C')

        v = message['v']
        n = message['n']
        d = message['d']
        sm = message['sm']
        if sm == False and self.prepared != (v, n, d):
            log = f'No Prepared for {self.server_id} with v={v} n={n} d={d}!!!'
            self.local_logs.append(log)
            # print(log)
            return
        log = f'committing on server {self.server_id}: prepared: {self.prepared}'
        self.local_logs.append(log)
        # print(log)

        self.update_transaction_status(self.accepted_number[1], 'C')

        client_id = self.message[1][0]
        self.execute_transaction(client_id)

        # self.clear_outdated_logs(major_block) 
        self.reset_local_values()

    def assign_n(t):
        return t[0]

    def digest(self, message):
        value = str(message)
        hash_object = hashlib.sha256(value.encode())
        hash_hex = hash_object.hexdigest()
        return hash_hex
    
    def get_node_signature(self, server_id):
        value = str(server_id)
        hash_object = hashlib.sha256(value.encode())
        hash_hex = hash_object.hexdigest()
        return hash_hex
    
    def clear_outdated_logs(self, major_block):
        mb_sequences = [item[0] for item in major_block]
        self.transactions_log = [transaction for transaction in self.transactions_log if transaction[0] not in mb_sequences]
        self.accepted_number = 0
        self.accepted_value = None

    def request_missing_blocks(self, leader_id, last_committed_block, requester_lcb):
        """Request missing blocks from the leader to catch up."""
        request_message = {
            'pbft': {
                'type': 'catch_up_request',
                'sender_id': self.server_id,
                'last_committed_block': last_committed_block,
            }
        }
        leader_port = self.find_port(leader_id)
        self.send_message(leader_port, request_message)

    def handle_catch_up_request(self, message):
        last_committed_block = message['last_committed_block']
        requester_id = message['sender_id']

        # Find the missing blocks and send them to the requester
        missing_blocks = self.get_missing_blocks()
        response_message = {
            'pbft': {
                'type': 'catch_up_response',
                'sender_id': self.server_id,
                'missing_blocks': missing_blocks,
                'last_committed_block': last_committed_block
            }
        }
        requester_port = self.find_port(requester_id)
        self.send_message(requester_port, response_message)

    def handle_catch_up_response(self, message):
        # Append missing blocks to the datastore
        missing_blocks = message['missing_blocks']
        lcm_ballot = message['last_committed_block']
        self.replace_datastore(missing_blocks)
        self.last_committed_block = lcm_ballot
        self.clear_outdated_logs(missing_blocks)  # Clear the local log as it's now committed
        # print(f"Server {self.server_id}: Caught up with missing blocks.")

    def calculate_performance(self):
        # Time since the server started
        elapsed_time = time.time() - self.start_time

        # Calculate average processing time per transaction
        if self.total_transactions_committed > 0:
            avg_processing_time = self.total_transaction_time / self.total_transactions_committed
        else:
            avg_processing_time = 0

        # Calculate transactions per second
        if elapsed_time > 0:
            transactions_per_second = self.total_transactions_committed / elapsed_time
        else:
            transactions_per_second = 0

        print(f"Server {self.server_id} Performance:")
        print(f" - Avg Processing Time per Transaction: {avg_processing_time:.4f} seconds")
        print(f" - Transactions Committed per Second: {transactions_per_second:.4f}")

    # -------- Commands -------- #
    def logs_dump(self):
        print()
        for log in self.local_logs:
            print(f'{log}')

    def print_status_by_seq_num(self, command):
        n = command['n']
        status = self.get_transactions_by_seq(n)
        print(f'\nServer {self.server_id}: n={n} status is {status}')

    def db_dump(self):
        self.cursor.execute(f"PRAGMA table_info(transactions)")
        columns = [column[1] for column in self.cursor.fetchall()]

        # Print column names
        if self.server_id not in Shared.byzantines:
            self.calculate_all_balances()
        label_balances = {Shared.number_to_label[number]: balance for number, balance in self.balances.items() if number in Shared.number_to_label}
        print("\nColumns:", columns)
        print(f'Server {self.server_id} datastore dump:\n{label_balances}')

    def print_view(self):
        print(f'\n printing new views on server {self.server_id}: {self.new_view_logs}')

    def performance_request(self):
        self.calculate_performance()
        message = {'command': {
        'type': 'performance_response',
        }}
        for peer_port in self.peers:
            self.send_message(peer_port, message)

    def performance_response(self):
        self.calculate_performance()

    def client_balance_request(self, command):
        client = command['client']
        message = {
            'command': {
                'type': 'client_balance_response',
                'sender_id': self.server_id,
                'client': client,
            }
        }
        for peer_port in self.peers:
            self.send_message(peer_port, message)
        print(f'Client {client} total balance is {self.calculate_balance(client)} in server {self.server_id}')

    def client_balance_response(self, message):
        sender_id = message['sender_id']
        client = message['client']
        balance = self.calculate_balance(client)
        print(f'Client {client} total balance is {balance} in server {self.server_id}')

    # -------- Helper Methods -------- #

    def generate_partial_signature(self, message_digest):
        return self.key_share

    def verify_threshold_signature(self, threshold_signature, message_digest):
        return self.public_key.verify(threshold_signature, message_digest)

    def find_port(self, sender_id):
        return next((item for item in self.peers if item % 1000 == sender_id), None)

    def calculate_all_balances(self):
        all_transactions = []
        datastore = self.get_transactions_by_status('E')
        for trans in datastore:
            id, sequence_number, s, r, amount, ballot_number, process_id = trans
            sender = Shared.get_number_for_alphabet(s)
            receiver = Shared.get_number_for_alphabet(r)
            all_transactions.append([sequence_number, [sender, receiver, amount]])
        sorted_transactions = sorted(all_transactions, key=lambda t: t[0])

        self.balances = {key: 10 for key in range(1, NUM_CLIENTS + 1)}

        for transaction in sorted_transactions:
            sender, receiver, amount = transaction[1] 
            self.balances[sender] -= amount
            self.balances[receiver] += amount

    def calculate_balance(self, client):
        all_transactions = []
        datastore = self.get_transactions_by_status('E')
        for trans in datastore:
            id, sequence_number, s, r, amount, ballot_number, process_id = trans
            sender = Shared.get_number_for_alphabet(s)
            receiver = Shared.get_number_for_alphabet(r)
            all_transactions.append([sequence_number, [sender, receiver, amount]])
        sorted_transactions = sorted(all_transactions, key=lambda t: t[0])

        balance = INITIAL_BALANCE
        for transaction in sorted_transactions:
            sender, receiver, amount = transaction[1]  
            if sender == client:
                balance -= amount
            elif receiver == client:
                balance += amount
                
        self.balances[client] = balance
        return self.balances[client]

    def handle_consensus_completion(self):
        self.reset_local_values()
        self.pending_pbft = False
        self.process_queued_transactions()

    def reset_local_values(self):
        # print(f'server {self.server_id} is reseting! n = {self.accepted_number[1]} d = {self.accepted_value}')
        self.accepted_number = None
        self.accepted_value = None
        self.prepared = None
        self.message = None
        self.prepared_signatures = []
    
    def check_balance(self, client):
        self.calculate_balance(client)

    def send_message(self, peer_port, message):
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            peer_socket.connect(('localhost', peer_port))
            peer_socket.send(json.dumps(message).encode())
        finally:
            peer_socket.close()

    def process_queued_transactions(self):
        if self.transaction_queue:
            payload = self.transaction_queue.pop(0)
            # print(f"Server {self.server_id}: Processing queued transaction {payload}.")
            self.handle_transaction(payload)

    def get_missing_blocks(self):
        return self.get_all_transactions()

            
def send_request_to_client(client_port, request):
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        peer_socket.connect(('localhost', client_port))
        peer_socket.send(json.dumps(request).encode())
    except ConnectionRefusedError:
        print(f"Error: Could not connect to server on port {client_port}. Is the server running?")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        peer_socket.close()

def generate_signature(server_id):
    """Generate a simple signature for a server/client ID"""
    value = str(server_id)
    hash_object = hashlib.sha256(value.encode())
    hash_hex = hash_object.hexdigest()
    return hash_hex

def send_balance_request_to_client(client_port, client_to_query):
    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        peer_socket.connect(('localhost', client_port))
        
        # Create balance request
        request = {
            'request_type': Shared.REQUEST_TYPE_BALANCE,
            'client': {
                'id': client_to_query,
                'signature': generate_signature(client_to_query),
                'timestamp': time.time()
            },
            'balance_query': {
                'client_id': client_to_query,
                'query_id': int(time.time() * 1000)
            }
        }
        
        peer_socket.send(json.dumps(request).encode())
    except ConnectionRefusedError:
        print(f"Error: Could not connect to client on port {client_port}. Is the client running?")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        peer_socket.close()

def send_message_to_server(server_port, message):
    try:
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_socket.connect(('localhost', server_port))
        peer_socket.send(json.dumps(message).encode())
    except ConnectionRefusedError:
        print(f"Error: Could not connect to server on port {server_port}. Is the server running?")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        peer_socket.close()

def read_input_file(filename):
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        test_sets = {}
        current_set = None
        live_servers = None
        byzantines = None
        sequence_number = 0
        for row in reader:
            if row[0]:
                current_set = int(row[0])
                live_servers = eval(row[2].replace('S', ''))
                byzantines = eval(row[3].replace('S', ''))
                if current_set not in test_sets:
                    test_sets[current_set] = {'transactions': [], 'balance_requests': [], 'live_servers': live_servers, 'byzantines': byzantines}
            
            if row[1].startswith('balance('):
                client_letter = row[1][8:-1]
                client_id = Shared.get_number_for_alphabet(client_letter)
                test_sets[current_set]['balance_requests'].append((None, client_id))
            else:
                transaction = eval(Shared.convert_labels_to_keys(row[1]))
                sequence_number += 1
                test_sets[current_set]['transactions'].append((sequence_number, transaction))
    
    return test_sets

def start_client(client_id, port, init):
    client = PBFTClient(client_id, port, NUM_SERVERS)
    client.start_client(init)

def start_server(server_id, port, peers, init, set, key_share):
    db_file = f'dbs/server_{server_id}_{set}.db'
    # Remove the existing database file if it exists
    if os.path.exists(db_file):
        os.remove(db_file)
    server = PbftServer(server_id, port, peers, db_file, key_share)
    server.start_server(init)
    return server

def print_log(server_id):
    server_port = server_id + 5000
    message = {'command': {
        'type': 'print_log',
    }}
    send_message_to_server(server_port, message)

def print_status(sequence_number):
    message = {'command': {
        'type': 'print_status',
        'n': sequence_number,
    }}
    for i in range(1, NUM_SERVERS + 1):
        server_port = i + 5000
        send_message_to_server(server_port, message)

def print_db(server_id):
    server_port = server_id + 5000
    message = {'command': {
        'type': 'print_db',
    }}
    send_message_to_server(server_port, message)

def print_view():
    message = {'command': {
        'type': 'print_view',
    }}
    for i in range(1, NUM_SERVERS + 1):
        server_port = i + 5000
        send_message_to_server(server_port, message)

def performance(server_id):
    server_port = server_id + 5000
    message = {'command': {
        'type': 'performance_request',
    }}
    send_message_to_server(server_port, message)


# Main
def setup(NUM_SERVERS, NUM_CLIENTS, start_client, start_server, init, set):
    for client_id in range(1, NUM_CLIENTS + 1):
        thread = threading.Thread(target=start_client, args=(client_id, client_id + 8000, init), daemon=True)
        thread.start()
        time.sleep(0.1)

    threads = []
    ports = list(range(5001, 5001+NUM_SERVERS))
    for i in range(len(ports)):
        peers = [port for port in ports if port != ports[i]]
        key_share = key_shares[(i%8000)-1]
        try:
            thread = threading.Thread(target=start_server, args=(i + 1, ports[i], peers, init, set, key_share), daemon=True)
            thread.start()
            threads.append(thread)
            time.sleep(0.1)
        except Exception as e:
            print(f"Error starting server thread: {e}")

def calculate_expected_balances(transactions):
    """Calculate expected balances based on transactions"""
    balances = {i: INITIAL_BALANCE for i in range(1, NUM_CLIENTS + 1)}
    
    for transaction in transactions:
        seq_num, (sender, receiver, amount) = transaction
        if balances[sender] >= amount:  # Only process if sufficient balance
            balances[sender] -= amount
            balances[receiver] += amount
    
    return balances

def run_test_file(input_file, interactive=True, debug=False):
    """Run a single test file"""
    print(f"\n{'='*60}")
    print(f"Running tests from: {input_file}")
    print(f"{'='*60}")
    
    test_sets = read_input_file(input_file)
    global key_shares
    key_shares = generate_key_shares(token_bytes(32), NUM_SERVERS, threshold)
    
    for set_number, test_data in test_sets.items():
        setup(NUM_SERVERS, NUM_CLIENTS, start_client, start_server, set_number == 1, set_number)

        print(f"\nRunning Test Set {set_number}...")
        transactions = test_data['transactions']
        balance_requests = test_data.get('balance_requests', [])
        live_servers = test_data['live_servers']
        Shared.byzantines = test_data['byzantines']
        
        print(f"Live Servers: {live_servers}")
        print(f"Byzantine Servers: {Shared.byzantines}")
        print(f"Transactions: {len(transactions)}")
        print(f"Balance Requests: {len(balance_requests)}")
        
        # Execute transactions first
        for transaction in transactions:
            client_id = transaction[1][0]
            request = {'transaction': transaction, 'live_servers': live_servers}
            time.sleep(0.5)
            send_request_to_client(client_id+8000, request)
        
        # Wait for transactions to complete
        time.sleep(2)
        
        # Execute balance requests
        for balance_request in balance_requests:
            client_id = balance_request[1]
            # Send balance request to the client who is requesting their own balance
            send_balance_request_to_client(client_id + 8000, client_id)
            time.sleep(2)  # Delay between balance requests to prevent conflicts
        
        if interactive:
            while True:
                user_input = input(
                    f"\nTest Set {set_number} executed. Press Enter to continue to the next set, "
                    "or enter one of the following options:\n"
                    "1.X - Print Logs on Server X\n"
                    "2.X - Print Status for Server X\n"
                    "3.X - Print DB for Server X\n"
                    "4 - Print all -New View- messages\n"
                    "5.X - Performance of Server X\n"
                    "Your choice: "
                )
                if user_input == "":
                    break  # Move to the next set
                elif user_input.startswith('1.'):
                    server_id = int(user_input.split('.')[1])
                    print_log(server_id)
                elif user_input.startswith('2.'):
                    sequence_number = int(user_input.split('.')[1])
                    print_status(sequence_number)
                elif user_input.startswith('3.'):
                    server_id = int(user_input.split('.')[1])
                    print_db(server_id)
                elif user_input.startswith('4'):
                    print_view()
                elif user_input.startswith('5.'):
                    server_id = int(user_input.split('.')[1])
                    performance(server_id)
                else:
                    print("Invalid input. Try again.")
        else:
            print(f"Test Set {set_number} completed automatically.")
            time.sleep(2)  # Brief pause between sets
        
        # Debug mode: Print database balances for all servers
        if debug:
            print(f"\n{'='*60}")
            print(f"DEBUG: Database Balances for Test Set {set_number}")
            print(f"{'='*60}")
            
            # Calculate and print expected balances
            expected_balances = calculate_expected_balances(transactions)
            print(f"\nExpected Balances:")
            for client_id, balance in expected_balances.items():
                client_name = Shared.get_alphabet_for_number(client_id)
                print(f"  {client_name}: {balance}")
            
            print(f"\nActual Database Balances:")
            for server_id in range(1, NUM_SERVERS + 1):
                try:
                    print(f"\n--- Server {server_id} Database ---")
                    print_db(server_id)
                    time.sleep(0.1)  # Small delay to ensure message is sent
                except Exception as e:
                    print(f"Error reading database for server {server_id}: {e}")
            print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(description='Linear PBFT Consensus Protocol')
    parser.add_argument('--test', '-t', type=str, help='Run specific test file (e.g., input1.csv)')
    parser.add_argument('--all', '-a', action='store_true', help='Run all tests from input1.csv to input10.csv')
    parser.add_argument('--non-interactive', '-n', action='store_true', help='Run tests without interactive prompts')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug mode with automatic DB balance verification')
    
    args = parser.parse_args()
    
    if args.all:
        # Run all tests from 1 to 10
        print("Running all tests from input1.csv to input10.csv...")
        for i in range(1, 11):
            test_file = f'tests/input{i}.csv'
            if os.path.exists(test_file):
                run_test_file(test_file, interactive=not args.non_interactive, debug=args.debug)
            else:
                print(f"Warning: {test_file} not found, skipping...")
    elif args.test:
        # Run specific test file
        test_file = args.test
        if not test_file.startswith('tests/'):
            test_file = f'tests/{test_file}'
        if not test_file.endswith('.csv'):
            test_file += '.csv'
            
        if os.path.exists(test_file):
            run_test_file(test_file, interactive=not args.non_interactive, debug=args.debug)
        else:
            print(f"Error: Test file {test_file} not found!")
            sys.exit(1)
    else:
        # Default behavior - run input8.csv (backward compatibility)
        print("No arguments provided. Running default test (input8.csv)...")
        run_test_file('tests/input8.csv', interactive=True, debug=args.debug)

if __name__ == "__main__":
    main()
