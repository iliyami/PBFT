import socket
import threading
import json
from queue import Queue
import time
import csv
import sqlite3
import os
from client import PBFTClient
from shared import Shared
import hashlib

# Constants
INITIAL_BALANCE = 10
NUM_SERVERS = 7
NUM_CLIENTS = 10
F = (NUM_SERVERS - 1) // 3  # BPFT F
MAJORITY = 2*F + 1 #BPFT requires majority for prepare*, commit and checkpoint


# Sample server class handling TCP connections and Paxos protocol
class PaxosServer:
    round_number = 0
    pending_pbft = False
    def __init__(self, server_id, port, peers, db_file):
        self.server_id = server_id
        self.port = port
        self.live_servers = []
        self.peers = peers
        self.balances = {key: 10 for key in range(1, NUM_CLIENTS + 1)}
        self.view = 1
        self.accepted_value = None
        self.accepted_number = None
        self.prepared = None
        self.message = None
        self.signatures = []
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

        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS transactions
                               (id INTEGER PRIMARY KEY,
                                sequence_number int,
                                sender int,
                                receiver int,
                                amount INTEGER,
                                view INTEGER,
                                status TEXT)''')
        self.conn.commit()
        # self.transactions_log = []
        # self.local_major_block = []
        # self.ballot_number = 0
        # self.is_leader = False
        # self.last_committed_block = (0, 0)
        # self.promised_number = 0


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
        ''', (id, n, sender, receiver, amount, v, status))
            
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
            ''', (id, sequence_number, sender, receiver, amount, ballot_number, process_id))

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
    
    def update_transaction_status(self, sequence_number, new_status):
        new_cursor = self.conn.cursor()
        new_cursor.execute("UPDATE transactions SET status = ? WHERE sequence_number = ?", (new_status, sequence_number))
        self.conn.commit()
        new_cursor.close()


    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', self.port))
        server_socket.listen(5)
        print(f"Server {self.server_id} started on port {self.port}")
        
        # Start a thread for accepting client connections
        threading.Thread(target=self.accept_connections, args=(server_socket,)).start()

    def accept_connections(self, server_socket):
        while True:
            client_conn, _ = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_conn,)).start()

    def handle_client(self, conn):
        data = conn.recv(1024).decode()
        request = json.loads(data)
        if 'transaction' in request:
            self.handle_transaction(request)
        elif 'paxos' in request:
            self.handle_paxos_message(request['paxos'])
        elif'command' in request:
            self.handle_commands(request['command'])

    # ------------- Paxos Phases ----------------- #
    def handle_commands(self, command):
        command_type = command['type']
        if command_type == 'client_balance_request':
            self.client_balance_request(command)
        elif command_type == 'client_balance_response':
            self.client_balance_response(command)
        elif command_type == 'print_balance':
            self.client_balance(command)
        elif command_type == 'print_log':
            self.local_logs()
        elif command_type == 'print_db':
            self.db_dump()
        elif command_type == 'performance_request':
            self.performance_request()
        elif command_type == 'performance_response':
            self.performance_response()

    def handle_transaction(self, payload):
        client = payload['client']
        transaction = payload['transaction']
        self.live_servers = payload['live_servers']

        for request in self.transaction_queue:
            queued_request_timestamp = request['client']['timestamp']
            new_request_timestamp = client['timestamp']
            if queued_request_timestamp == new_request_timestamp:
                return
            
        if PaxosServer.pending_pbft:
            # print(f"Server {self.server_id}: Paxos is in progress. Queuing transaction {transaction}.")
            self.transaction_queue.append(payload)
            return
        
        # print(f"Server {self.server_id}: Queuing transaction {transaction}.")
        # self.transaction_queue.put(transaction)
        seq_num, trans = transaction
        sender, receiver, amount = trans
        self.check_balance(sender)
        # print(f'initializinggggggggggggggg PBFT for req {payload}')
        self.initiate_pbft(client, transaction)


    def handle_paxos_message(self, paxos_message):
        paxos_type = paxos_message['type']
        if paxos_type == 'preprepare':
            self.handle_pre_prepare(paxos_message)
        elif paxos_type == 'prepare':
            self.handle_prepare(paxos_message)
        elif paxos_type == 'prepare_ack':
            self.handle_prepare_ack(paxos_message)
        elif paxos_type == 'commit':
            self.handle_commit(paxos_message)
        elif paxos_type == 'commit_ack':
            self.handle_commit_ack(paxos_message)
        elif paxos_type == 'catch_up_request':
            self.handle_catch_up_request(paxos_message)
        elif paxos_type == 'catch_up_response':
            self.handle_catch_up_response(paxos_message)

    def broadcast_message(self, message):
        live_ports = [server + 5000 for server in self.live_servers if server != self.server_id]
        for peer_port in live_ports:
                self.send_message(peer_port, message) 

    def initiate_pbft(self, client, transaction):
        PaxosServer.pending_pbft = True
        self.message = transaction
        self.signatures = []
        self.majority_responses = 1
        self.majority_reached = False
        self.accept_majority_responses = 1
        self.accept_majority_reached = False

        # Send PRE-PREPARE message to all peers
        n = PaxosServer.assign_n()
        d = self.digest(transaction)
        self.view = self.server_id
        self.accepted_number = (self.server_id, n)
        self.accepted_value = d
        message = {'paxos': {
            'type': 'preprepare',
            'v': self.view,
            'n': n,
            'd': d,
            'm': transaction,
            'client': client,
            's': self.get_node_signature(self.server_id)
        }}
        self.broadcast_message(message)
        self.wait_for_majority()

    def handle_pre_prepare(self, message):
        n = message['n']
        v = message['v']
        m = message['m']
        d = message['d']
        signature = message['s']

        if self.accepted_number != None and self.accepted_number != (v, n):
            self.accepted_number = None
            self.accepted_value = None

        isValid = v == self.view and d == self.digest(m) and signature == self.get_node_signature(v) and (
            self.accepted_number == None or (self.accepted_number == (v, n) and self.accepted_value == d))

        if isValid:
            self.view = v
            self.accepted_number = (v, n)
            # print(f'server {self.server_id} acc num is {self.accepted_number} for n {n}')
            self.accepted_value = d
            self.message = m
             # Send PREPARE message to the collector (leader)
            leader_port = 5000+Shared.leader_id
            message = {'paxos': {
            'type': 'prepare',
            'v': v,
            'n': n,
            'd': d,
            's': self.get_node_signature(self.server_id),
            }}
            self.send_message(leader_port, message)
        else:
            print('PP Is nottttttttttttttttttttttttttttttt valiiiiiiiiiid')

    def handle_prepare(self, message):
        signature = message['s']
        
        # print(f'Receiving prepare by leader with payload: {message}')
        with self.response_lock:
            self.majority_responses += 1
            self.signatures.append(signature)
            # print(f'Receiving prepare by leader with payload: {message}')
            if self.majority_responses >= MAJORITY:
                # Majority reached, send ACCEPT message
                start_time = time.time()
                while time.time() - start_time < 0.6:
                    self.response_lock.release()
                    time.sleep(0.1)  # Wait for 200ms to avoid busy-waiting
                    self.response_lock.acquire()
                self.majority_reached = True
                self.majority_responses = 1
                # print('======================here\n',self.response_lock)
                self.condition.notify()
                # print('======================here\n',self.response_lock)

    def wait_for_majority(self, timeout=2):
        """Wait for majority of prepare responses or timeout"""
        with self.condition:
            # Wait until a majority is reached or the timeout occurs
            self.condition.wait_for(lambda: self.majority_reached, timeout=timeout)
            if self.majority_reached:
                # print(f"Server {self.server_id}: Majority of promises received, proceeding to send accept.")
                self.majority_reached = False
                self.majority_responses = 1
                # print('======================here\n',self.response_lock)
                # if self.response_lock.locked():
                #     self.response_lock.release()
                # print(f'send prepare ack for {self.accepted_number}')
                self.send_prepare_ack()
            else:
                print(f"Server {self.server_id}: Timeout reached, aborting Paxos.")
                self.majority_reached = False 
                self.majority_responses = 1


    def send_prepare_ack(self):
        message = {'paxos': {
                'type': 'prepare_ack',
                'v': self.server_id,
                'n': self.accepted_number[1],
                'certificate': self.signatures,
            }}
        self.broadcast_message(message)
        self.wait_for_accepted_majority()


    def handle_prepare_ack(self, message):
        signatures = message['certificate']
        v = message['v']
        n = message['n']

        isValid = len(signatures) >= MAJORITY and (self.accepted_number != None or self.accepted_number == (v, n))
        if isValid == False:
            return

         # Send Commit message to the collector (leader)
        leader_port = 5000+Shared.leader_id
        message = {'paxos': {
            'type': 'commit',
            'v': self.view,
            'n': self.accepted_number[1],
            'd': self.accepted_value,
            'i': self.server_id,
            's': self.get_node_signature(self.server_id)
        }}
        self.prepared = (self.accepted_number[0], self.accepted_number[1], self.accepted_value)
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
                self.commit_transaction()
                # print(f"Server {self.server_id}: Majority reached, committing request {self.message} .")
            else:
                print(f"Server {self.server_id}: Timeout reached for the commit majority!")
                self.accept_majority_reached = False
                self.accept_majority_responses = 1


    def handle_commit(self, message):
        with self.accept_response_lock:
                d = message['d']
                n = message['n']
                v = message['v']
                s = message['s']
                if (v, n) != self.accepted_number or d != self.accepted_value:
                    return
                
                self.accept_majority_responses += 1
                # print(f"Server {self.server_id}: Received commit request with s {s}")

                if self.accept_majority_responses >= MAJORITY:
                    self.accept_majority_reached = True
                    self.accept_condition.notify()
                    # print(f"Server {self.server_id}: Reached majority, committing request {message}")

    def commit_transaction(self):
        # Commit the block locally
        start_time = time.time()
        self.add_transaction_to_datastore(self.message, self.accepted_number, 'C')
        # self.clear_outdated_logs(unique_major_block)

        # Update performance metrics
        processing_time = time.time() - start_time  # Calculate processing time
        self.total_transaction_time += processing_time
        self.total_transactions_committed += 1

        # Execution
        client_id = self.message[1][0]
        self.execute_transaction(client_id)

        # Broadcast COMMIT_ACK message to all other servers
        live_ports = [server + 5000 for server in self.live_servers if server != self.server_id]
        message = {
            'paxos': {
                'type': 'commit_ack',
                'v': self.view,
                'n': self.accepted_number[1],
                'd': self.digest(self.message),
                'i': self.server_id,
                's': self.get_node_signature(self.server_id),
            }
        }
        self.broadcast_message(message)
        # print(f'handling post consensusssssssssssssssssss n = {self.accepted_number[1]}')
        threading.Timer(0.2, self.handle_consensus_completion).start()

    def execute_transaction(self, client_id):
        transactions = self.get_all_transactions()
        commited = []
        executed = []
        for trans in transactions:
            id, n, sender, receiver, amount, view, status = trans
            if status == 'C':
                commited.append(trans)
            elif status == 'E':
                executed.append(trans)

        if len(commited) == 0:
            self.send_message(client_id+8000, message = {'reply': 'yes'})
            return

        for commit in commited:
            last_exec_n = 0 if len(executed) == 0 else executed[-1][1]
            id, n, sender, receiver, amount, view, status = commit
            if last_exec_n + 1 == n:
                print(f"Server {self.server_id}: Processed transaction n = {n} ({sender} -> {receiver}: {amount})")
                self.balances[sender] -= amount
                self.balances[receiver] += amount
                executed.append(commit)
                self.update_transaction_status(n, 'E')
                client_port = sender + 8000
                self.send_message(client_port, message = {'reply': 'yes'})


    def handle_commit_ack(self, message):
        v = message['v']
        n = message['n']
        d = message['d']
        if self.prepared != (v, n, d):
            # print(f'No Prepared for {self.server_id} with n={n} d={d}!!!!!!!!!!')
            return
        # print(f'messageeeeeeeeeeeeeeeee server {self.server_id}: {message}')
        # Commit the major block to the datastore
        self.add_transaction_to_datastore(self.message, self.accepted_number, 'C')
        # Execution
        client_id = self.message[1][0]
        self.execute_transaction(client_id)
        # self.clear_outdated_logs(major_block) 
        self.reset_local_values()

    def assign_n():
        PaxosServer.round_number += 1
        return PaxosServer.round_number

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
            'paxos': {
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
            'paxos': {
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
    def client_balance(self, command):
        client = command['client']
        if (client == None):
            print('Wrong request format!')
        balance = self.calculate_balance(client)
        print(f'Client {client} balance on server {self.server_id} is {balance}')

    def local_logs(self):
        print(f'Server {self.server_id} local logs:\n{self.transactions_log}')

    def db_dump(self):
        print(f'Server {self.server_id} datastore dump:\n{self.get_all_transactions()}')

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

    def find_port(self, sender_id):
        return next((item for item in self.peers if item % 1000 == sender_id), None)

    def calculate_balance(self, client):
        all_transactions = []
        datastore = self.get_transactions_by_status('E')
        for trans in datastore:
            id, sequence_number, sender, receiver, amount, ballot_number, process_id = trans
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
        PaxosServer.pending_pbft = False
        self.process_queued_transactions()

    def reset_local_values(self):
        # print(f'server {self.server_id} is reseting! n = {self.accepted_number[1]} d = {self.accepted_value}')
        self.accepted_number = None
        self.accepted_value = None
        self.prepared = None
        self.message = None
        self.signatures = []
    
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
        sequence_number = 0
        for row in reader:
            if row[0]:
                current_set = int(row[0])
                live_servers = eval(row[2].replace('S', ''))
                if current_set not in test_sets:
                    test_sets[current_set] = {'transactions': [], 'live_servers': live_servers}
            
            transaction = eval(row[1].replace('S', ''))
            sequence_number += 1
            
            test_sets[current_set]['transactions'].append((sequence_number, transaction))
    
    return test_sets

def start_client(client_id, port):
    client = PBFTClient(client_id, port)
    client.start_client()
    clients.append(client)

def start_server(server_id, port, peers):
    db_file = f'dbs/server_{server_id}.db'
    # Remove the existing database file if it exists
    if os.path.exists(db_file):
        os.remove(db_file)
    server = PaxosServer(server_id, port, peers, db_file=db_file)
    server.start_server()
    return server

def print_balance(client, server_id):
    server_port = server_id + 5000
    message = {'command': {
        'type': 'print_balance',
        'client': client,
    }}
    send_message_to_server(server_port, message)

def print_log(server_id):
    server_port = server_id + 5000
    message = {'command': {
        'type': 'print_log',
    }}
    send_message_to_server(server_port, message)

def print_db(server_id):
    server_port = server_id + 5000
    message = {'command': {
        'type': 'print_db',
    }}
    send_message_to_server(server_port, message)

def performance(server_id):
    server_port = server_id + 5000
    message = {'command': {
        'type': 'performance_request',
    }}
    send_message_to_server(server_port, message)

def print_balance_across_servers(client):
    message = {'command': {
        'type': 'client_balance_request',
        'client': client
    }}
    send_message_to_server(leader_port, message)



# Main
clients = []
for client_id in range(1, NUM_CLIENTS + 1):
    thread = threading.Thread(target=start_client, args=(client_id, client_id + 8000), daemon=True)
    thread.start()
    time.sleep(0.1)

threads = []
ports = list(range(5001, 5001+NUM_SERVERS))
for i in range(len(ports)):
    peers = [port for port in ports if port != ports[i]]
    try:
        thread = threading.Thread(target=start_server, args=(i + 1, ports[i], peers), daemon=True)
        thread.start()
        threads.append(thread)
        time.sleep(0.1)
    except Exception as e:
        print(f"Error starting server thread: {e}")

test_sets = read_input_file('tests/input.csv')
for set_number, test_data in test_sets.items():
    print(f"Running Test Set {set_number}...")
    transactions = test_data['transactions']
    live_servers = test_data['live_servers']
    
    for transaction in transactions:
        client_id = transaction[1][0]  # S is the sender, which determines the client
        leader_port = 5000 + Shared.leader_id
        
        # If the server is in the live_servers, send the transaction to that server
        if leader_port%1000 in live_servers:
            # print(f"Sending request to client {client_id}")
            client = clients[client_id - 1]
            request = {'transaction': transaction, 'live_servers': live_servers}
            send_request_to_client(client_id+8000, request)
        else:
            print(f"Server {leader_port} is down, skipping transaction {transaction}")
    
    while True:
        user_input = input(
            f"\nTest Set {set_number} executed. Press Enter to continue to the next set, "
            "or enter one of the following options:\n"
            "1.X.Y - Print Balance for Client X on Server Y\n"
            "2.X - Print Log for Server X\n"
            "3.X - Print DB for Server X\n"
            "4.X - Performance of Server X\n"
            "5.X (Bonus) - Aggregated Client X Balance Across All Servers"
            "Your choice: "
        )
        if user_input == "":
            break  # Move to the next set
        elif user_input.startswith('1.'):
            try:
                _, client_id, server_id = map(int, user_input.split('.'))
                print_balance(client_id, server_id)
            except ValueError:
                print("Invalid format for PrintBalance. Use 1.X.Y (e.g., 1.1.2 for client 1 on server 2)")
        elif user_input.startswith('2.'):
            server_id = int(user_input.split('.')[1])
            print_log(server_id)
        elif user_input.startswith('3.'):
            server_id = int(user_input.split('.')[1])
            print_db(server_id)
        elif user_input.startswith('4.'):
            server_id = int(user_input.split('.')[1])
            performance(server_id)
        elif user_input.startswith('5.'):
            client_id = int(user_input.split('.')[1])
            print_balance_across_servers(client_id)
        else:
            print("Invalid input. Try again.")
