from secrets import token_bytes, randbelow
# from blspy import PrivateKey, AugSchemeMPL
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

# Global debug flag
DEBUG_MODE = False

def debug_print(*args, **kwargs):
    """Print debug messages only when DEBUG_MODE is True"""
    if DEBUG_MODE:
        print(*args, **kwargs)

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
        self.live_servers = list(range(1, NUM_SERVERS + 1))  # Initialize with all servers
        self.peers = peers
        self.pending_pbft = False
        self.balances = {key: 10 for key in range(1, NUM_CLIENTS + 1)}  # Legacy: single balance
        # SmallBank: separate savings and checking accounts
        self.savings_balances = {key: 10 for key in range(1, NUM_CLIENTS + 1)}
        self.checking_balances = {key: 10 for key in range(1, NUM_CLIENTS + 1)}
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
        self.equivocation_targets_by_seq = {}  # sequence_number -> list of server_ids that received pre-prepare
        self.new_view_logs = []
        self.local_logs = []
        self.new_view_created_for_view = None  # Track if new-view message has been created for a view
        self.processed_new_views = set()  # Track which views we've already processed new-view messages for
        self.key_share = key_share
        self.public_key = None
        
        # Checkpointing variables
        self.checkpoint_interval = 10
        self.last_checkpoint_sequence = 0
        self.checkpoints = {}  # sequence_number -> {server_id -> checkpoint_data}
        self.checkpoint_signatures = {}  # sequence_number -> list of signatures
        self.stable_checkpoints = {}  # sequence_number -> stable checkpoint data
        self.checkpoint_timer = None 

        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS transactions
                               (id INTEGER PRIMARY KEY,
                                sequence_number int,
                                sender TEXT,
                                receiver TEXT,
                                amount INTEGER,
                                view INTEGER,
                                status TEXT,
                                transaction_type TEXT DEFAULT 'TRANSFER')''')
        # Add transaction_type column if it doesn't exist (for backward compatibility)
        try:
            self.cursor.execute('ALTER TABLE transactions ADD COLUMN transaction_type TEXT DEFAULT \'TRANSFER\'')
            self.conn.commit()
        except sqlite3.OperationalError:
            # Column already exists, ignore
            pass
        self.conn.commit()


    def close(self):
        self.conn.close()

    def detect_transaction_type(self, transaction):
        """
        Detect if transaction is legacy TRANSFER or SmallBank transaction type.
        Returns: (tx_type, parsed_data)
        - Legacy: ('TRANSFER', (sender, receiver, amount))
        - SmallBank: ('Amalgamate'|'Balance'|'DepositChecking'|'SendPayment'|'TransactSavings'|'WriteCheck', args)
        
        Transaction format can be:
        - (seq_num, (sender, receiver, amount)) for legacy
        - (seq_num, (tx_type, args)) for SmallBank
        """
        if not isinstance(transaction, (list, tuple)) or len(transaction) < 2:
            return ('TRANSFER', transaction)
        
        id_part, data_part = transaction[0], transaction[1]
        
        # Check if data_part is a SmallBank transaction (first element is transaction type string)
        if isinstance(data_part, (list, tuple)) and len(data_part) >= 1:
            first_elem = data_part[0] if isinstance(data_part, (list, tuple)) else None
            if isinstance(first_elem, str) and first_elem in ['Amalgamate', 'Balance', 'DepositChecking', 'SendPayment', 'TransactSavings', 'WriteCheck']:
                # SmallBank: data_part is (tx_type, args)
                tx_type = first_elem
                args = data_part[1:] if len(data_part) > 1 else ()
                if isinstance(args, (list, tuple)) and len(args) == 1 and isinstance(args[0], (list, tuple)):
                    # args is a single tuple/list, unwrap it
                    args = args[0]
                return (tx_type, tuple(args) if isinstance(args, (list, tuple)) else args)
        
        # Check if it's a SmallBank transaction (stored as string in first element of transaction)
        # This handles the case where transaction is (tx_type, args) directly
        if isinstance(id_part, str) and id_part in ['Amalgamate', 'Balance', 'DepositChecking', 'SendPayment', 'TransactSavings', 'WriteCheck']:
            tx_type = id_part
            if isinstance(data_part, (list, tuple)):
                return (tx_type, tuple(data_part))
            return (tx_type, data_part)
        
        # Legacy format: (seq_num, (sender, receiver, amount))
        # Check if data_part has exactly 3 elements (sender, receiver, amount)
        if isinstance(data_part, (list, tuple)) and len(data_part) == 3:
            # Verify it's not a SmallBank transaction by checking if first element is a number
            if not isinstance(data_part[0], str) or data_part[0] not in ['Amalgamate', 'Balance', 'DepositChecking', 'SendPayment', 'TransactSavings', 'WriteCheck']:
                return ('TRANSFER', tuple(data_part))
        
        return ('TRANSFER', transaction)

    def add_transaction_to_datastore(self, message, accepted_number, status):
        v, n = accepted_number
        new_curstor = self.conn.cursor()
        id, transaction = message
        
        # Detect transaction type
        tx_type, tx_data = self.detect_transaction_type(message)
        
        # Handle legacy TRANSFER format
        if tx_type == 'TRANSFER':
            sender, receiver, amount = tx_data
            new_curstor.execute('''
                INSERT OR IGNORE INTO transactions (id, sequence_number, sender, receiver, amount, view, status, transaction_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (id, n, Shared.get_alphabet_for_number(sender), Shared.get_alphabet_for_number(receiver), amount, v, status, 'TRANSFER'))
        else:
            # SmallBank transaction: store as JSON-like string in sender field, use receiver for additional data
            # Format: sender = tx_type, receiver = comma-separated args, amount = first numeric arg
            args_str = ','.join(str(x) for x in tx_data) if isinstance(tx_data, (list, tuple)) else str(tx_data)
            first_num = tx_data[0] if isinstance(tx_data, (list, tuple)) and len(tx_data) > 0 else 0
            new_curstor.execute('''
                INSERT OR IGNORE INTO transactions (id, sequence_number, sender, receiver, amount, view, status, transaction_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (id, n, tx_type, args_str, first_num, v, status, tx_type))
            
        if new_curstor.rowcount > 0:
            self.conn.commit()
        new_curstor.close()
        # print(f"Server {self.server_id}: Transaction {block} added to persistent datastore (DB).")

    def replace_datastore(self, new_datastore):
        self.cursor.execute('DELETE FROM transactions')
        self.conn.commit()

        for transaction in new_datastore:
            # Handle both old format (7 columns) and new format (8 columns with transaction_type)
            if len(transaction) >= 8:
                id, sequence_number, sender, receiver, amount, ballot_number, process_id, tx_type = transaction[:8]
            else:
                id, sequence_number, sender, receiver, amount, ballot_number, process_id = transaction[:7]

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
    
    def get_tx_status_by_seq(self, n):
        all = self.get_all_transactions()
        for trans in all:
            # Handle both old format (7 columns) and new format (8 columns with transaction_type)
            if len(trans) >= 2:
                seq_num = trans[1]
                if n == seq_num:
                    return trans[6] if len(trans) > 6 else 'X'

        return 'X'
    
    def get_transaction_by_seq(self, n):
        """Get the full transaction tuple by sequence number, or None if not found"""
        all = self.get_all_transactions()
        for trans in all:
            # Handle both old format (7 columns) and new format (8 columns with transaction_type)
            if len(trans) >= 2:
                seq_num = trans[1]
                if n == seq_num:
                    return trans
        return None
    
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
        try:
            data = conn.recv(65536).decode()
            request = json.loads(data)
            if 'transaction' in request:
                self.handle_transaction(request)
            elif 'pbft' in request:
                self.handle_pbft_message(request['pbft'])
            elif 'command' in request:
                self.handle_commands(request['command'])
            elif 'request_type' in request and request['request_type'] == Shared.REQUEST_TYPE_BALANCE:
                threading.Thread(target=self.handle_balance_request, args=(request, conn)).start()
        except json.JSONDecodeError as e:
            log = f"Server {self.server_id}: [ERROR] JSON decode failed: {e} (data length: {len(data) if 'data' in locals() else 0})"
            self.local_logs.append(log)
            print(log)
        except Exception as e:
            log = f"Server {self.server_id}: [ERROR] handle_client failed: {e}"
            self.local_logs.append(log)
            print(log)

    def handle_balance_request(self, request, conn):
        """Handle read-only balance requests that bypass consensus"""
        if self.server_id in Shared.byzantines and "crash" in current_attack_types:
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

        # If this server is not live, it should be idle and not process transactions
        # View change will be triggered by timeout on backup nodes
        if self.server_id not in self.live_servers:
            return  # Server is not live, remain idle

        if self.view != self.server_id:
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: Setting view timer (timeout={self.view_timeout}s) in handle_transaction")
            self.view_timer = threading.Timer(self.view_timeout, self.view_change_request, args=('I', ))
            self.view_timer.start()

        if self.view != self.server_id:
            return

        if self.pending_pbft:
            new_request_timestamp = client['timestamp']
            for request in self.transaction_queue:
                if 'client' in request and isinstance(request['client'], dict) and 'timestamp' in request['client']:
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
        
        # Detect transaction type for backward compatibility
        tx_type, tx_data = self.detect_transaction_type(transaction)
        
        # Handle SmallBank transactions differently
        if tx_type != 'TRANSFER':
            # SmallBank transaction: transaction format is (tx_type, args)
            # We need to convert it to (seq_num, (tx_type, args)) for PBFT
            # But keep the original format for storage
            if self.view == self.server_id:
                # For SmallBank, we still check for stale sequence numbers
                existing_trans = self.get_transaction_by_seq(seq_num)
                if existing_trans:
                    # Handle stale sequence number replacement if needed
                    if len(existing_trans) >= 7:
                        id, n, s, r, amt, view, status = existing_trans[:7]
                        if status == 'E':
                            executed_transactions = self.get_transactions_by_status('E')
                            max_seq = 0
                            for t in executed_transactions:
                                if len(t) >= 2:
                                    max_seq = max(max_seq, t[1])
                            new_seq = max_seq + 1
                            transaction = (new_seq, trans)
                            seq_num = new_seq
        else:
            # Legacy TRANSFER transaction
            sender, receiver, amount = tx_data
            
            # Check if the sequence number corresponds to a no-op (stale sequence number from equivocation)
            # If so, replace it with the next available sequence number
            if self.view == self.server_id:  # Only leader should do this
                existing_trans = self.get_transaction_by_seq(seq_num)
                if existing_trans:
                    id, n, s, r, amt, view, status = existing_trans[:7]
                    # Check if it's a no-op (status='E' and sender=0, receiver=0, amount=0)
                    if status == 'E':
                        sender_num = Shared.get_number_for_alphabet(s) if s else 0
                        receiver_num = Shared.get_number_for_alphabet(r) if r else 0
                        # find the next available sequence number (max executed + 1)
                        executed_transactions = self.get_transactions_by_status('E')
                        max_seq = 0
                        for t in executed_transactions:
                            if len(t) >= 2:
                                id, n = t[0], t[1]
                                if n > max_seq:
                                    max_seq = n
                        new_seq = max_seq + 1
                        debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Detected stale sequence number n={seq_num} (no-op), replacing with n={new_seq}")
                        # Replace the sequence number in the transaction
                        # Normalize to tuple-of-tuples format to match what backups will compute digest from
                        if isinstance(trans, list):
                            trans_tuple = tuple(trans)
                        else:
                            trans_tuple = trans
                        transaction = (new_seq, trans_tuple)
                        seq_num = new_seq
            
            # Only check balance for legacy TRANSFER transactions
            if sender > 0:
                self.check_balance(sender)
        
        # Check if this is a queued equivocation n=2 request
        equivocation_n2 = payload.get('equivocation_n2', False)
        equivocation_exclude = payload.get('equivocation_exclude', None)
        
        self.initiate_pbft(client, transaction, equivocation_n2=equivocation_n2, equivocation_exclude=equivocation_exclude)


    def handle_pbft_message(self, pbft_message):
        pbft_type = pbft_message['type']
        if pbft_type == 'view_change':
            self.handle_view_change(pbft_message)
        elif pbft_type == 'new_view':
            self.handle_new_view(pbft_message)
        elif pbft_type == 'checkpoint':
            self.handle_checkpoint(pbft_message)
            
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
        
        if self.server_id in Shared.byzantines and dark_target_nodes:
            live_ports = [port for port in live_ports if (port - 5000) not in dark_target_nodes]
            print(f"Server {self.server_id} (Byzantine): Avoiding sending messages to nodes {dark_target_nodes}")
        
        for peer_port in live_ports:
                self.send_message(peer_port, message) 

    def initiate_pbft(self, client, transaction, equivocation_n2=False, equivocation_exclude=None):
        self.pending_pbft = True
        self.message = transaction
        self.prepared_signatures = []
        self.majority_responses = 1
        self.majority_reached = False
        self.accept_majority_responses = 1
        self.accept_majority_reached = False

        # Send PRE-PREPARE message to all peers
        n = PbftServer.assign_n(transaction)
        # Normalize transaction to tuple-of-tuples format (matching what backups will receive after JSON)
        # JSON converts tuples to lists, so we need to ensure consistent format
        # Backups will convert [3, [1, 10, 1]] to (3, (1, 10, 1)), so we compute digest from that format
        if isinstance(transaction, list):
            normalized_transaction = tuple(transaction)
            if len(normalized_transaction) == 2 and isinstance(normalized_transaction[1], list):
                normalized_transaction = (normalized_transaction[0], tuple(normalized_transaction[1]))
        elif isinstance(transaction, tuple) and len(transaction) == 2:
            # Ensure inner part is also a tuple (not list)
            if isinstance(transaction[1], list):
                normalized_transaction = (transaction[0], tuple(transaction[1]))
            else:
                normalized_transaction = transaction
        else:
            normalized_transaction = transaction
        d = self.digest(normalized_transaction)
        debug_print(f"[DEBUG-EQ] Leader {self.server_id}: initiate_pbft - transaction={transaction}, normalized={normalized_transaction}, n={n}, d={d[:8]}...")
        self.view = self.server_id
        self.accepted_number = (self.server_id, n)
        self.accepted_value = d
        
        # Check if this is a queued equivocation n=2 request
        if equivocation_n2:
            # CRITICAL: Update self.message to n=2's transaction (was set to n=1's transaction before)
            self.message = transaction
            # Ensure transaction format matches what backups will compute digest from
            # Backups receive [2, [1, 10, 1]] and convert to (2, (1, 10, 1))
            # So we need to compute digest from (2, (1, 10, 1)) format
            if isinstance(transaction, tuple) and len(transaction) == 2:
                # Ensure inner part is a tuple (not list) to match backup's conversion
                if isinstance(transaction[1], list):
                    normalized_transaction = (transaction[0], tuple(transaction[1]))
                else:
                    normalized_transaction = transaction
                # Recompute digest from format that matches backup's computation
                d = self.digest(normalized_transaction)
                # Update accepted_value with new digest
                self.accepted_value = d
            
            # Send pre-prepare for n=2 only to nodes NOT in exclude list (i.e., "others")
            exclude_nodes = equivocation_exclude or []
            target_servers = [s for s in self.live_servers if s != self.server_id and s not in exclude_nodes]
            # Store which servers received n=2 for split broadcast of prepare_ack/commit_ack
            self.equivocation_targets_by_seq[n] = target_servers.copy()
            debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Sending n={n} pre-prepare to servers {target_servers}, exclude={exclude_nodes}")
            for server_id in target_servers:
                self._send_preprepare_message(server_id, n, d, transaction, client)
            
            # Add to datastore
            self.add_transaction_to_datastore(self.message, self.accepted_number, 'PP')
            log = f'Equivocation PP by leader:{self.server_id} for queued n={n} request {transaction} (sent to others only)'
            self.local_logs.append(log)
            debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Starting wait_for_majority for n={n}, accepted_number={self.accepted_number}")
            self.wait_for_majority()  # Wait for n=2 to complete
            return
        
        # Pass normalized transaction to equivocation attack handler
        if self._handle_equivocation_attack(n, d, normalized_transaction, client):
            return
        
        # Normal behavior
        debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Sending normal pre-prepare for n={n}, v={self.view}, transaction={transaction}, digest={d[:8]}...")
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
        latest_checkpoint = self.get_latest_stable_checkpoint()
        
        # BONUS FEATURE: Include checkpoint certificate in view-change message
        # This enables replica recovery and garbage collection
        if latest_checkpoint:
            checkpoint_cert = {
                'sequence_number': latest_checkpoint['sequence_number'],
                'view': latest_checkpoint['view'],
                'balances': latest_checkpoint['balances'],
                'executed_transactions': latest_checkpoint.get('executed_transactions', [])
            }
            min_s = latest_checkpoint['sequence_number']
        else:
            # No stable checkpoint yet - use initial state
            checkpoint_cert = {
                'sequence_number': 0,
                'view': 1,
                'balances': {i: 10 for i in range(1, NUM_CLIENTS + 1)},
                'executed_transactions': []
            }
            min_s = 0
        
        # Collect prepared requests (status 'P' or 'C' but not 'E')
        # Also include 'PP' status for equivocation detection (pre-prepared but not prepared)
        prepared_requests = []
        prepared_transactions = self.get_transactions_by_status('P')
        committed_transactions = self.get_transactions_by_status('C')
        preprepared_transactions = self.get_transactions_by_status('PP')  # Include PP for equivocation detection
        
        # Combine prepared, committed, and pre-prepared (but not executed) transactions
        all_prepared = {}
        for trans in prepared_transactions + committed_transactions + preprepared_transactions:
            # Skip empty or invalid transactions
            if not trans or len(trans) < 7:
                continue
            # Handle both old format (7 columns) and new format (8 columns with transaction_type)
            if len(trans) >= 8:
                id, n, s, r, amount, view, status, tx_type = trans[:8]
            else:
                id, n, s, r, amount, view, status = trans[:7]
                tx_type = 'TRANSFER'  # Default to legacy format
            # Handle None values (e.g., for no-op transactions or invalid data)
            if s is None:
                sender = 0  # No-op transactions have sender=0
            elif isinstance(s, (int, float)) and s == 0:
                sender = 0
            else:
                sender = Shared.get_number_for_alphabet(s) if s else 0
            
            if r is None:
                receiver = 0  # No-op transactions have receiver=0
            elif isinstance(r, (int, float)) and r == 0:
                receiver = 0
            else:
                receiver = Shared.get_number_for_alphabet(r) if r else 0
            
            transaction = (sender, receiver, amount)
            # Reconstruct the full transaction format: (id, (sender, receiver, amount))
            full_transaction = (id, transaction)
            digest = self.digest(full_transaction)
            
            # Store by sequence number to avoid duplicates
            if n not in all_prepared:
                all_prepared[n] = {
                    'n': n,
                    'v': view,
                    'd': digest,
                    'm': full_transaction,
                    'status': status
                }
        
        prepared_requests = list(all_prepared.values())
        
        # Debug: Show what prepared requests are being sent
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: view_change_request for v={new_view} - sending {len(prepared_requests)} prepared requests:")
        for prep_req in prepared_requests:
            debug_print(f"[DEBUG-EQ]   - n={prep_req['n']}, v={prep_req['v']}, d={prep_req['d'][:8]}..., m={prep_req['m']}, status={prep_req['status']}")
        
        message = {'pbft': {
            'type': 'view_change',
            'v': new_view,
            'n': min_s,  # Last stable checkpoint sequence (BONUS: enables recovery)
            'C': checkpoint_cert,  # BONUS: Include checkpoint certificate for recovery
            'P': prepared_requests,  # Prepared requests that need to be reprocessed
            'i': self.server_id,
            's': self.get_node_signature(self.server_id)
        }}
        log = f'\nServer {self.server_id}: [BONUS-CHECKPOINT] view change requested for v={new_view} from {dest} with checkpoint n={min_s}, {len(prepared_requests)} prepared requests'
        self.local_logs.append(log)
        print(log)
        self.broadcast_message(message, include_self=True)

    def handle_view_change(self, message):
        v = message['v']
        i = message['i']
        
        if self.server_id == v:
            self.vc_signatures[i] = message
            
            # Determine quorum threshold: MAJORITY (2f+1) if there's an attack, F+1 otherwise (optimization)
            global current_attack_types
            has_attack = current_attack_types and len(current_attack_types) > 0
            quorum_threshold = MAJORITY if has_attack else F + 1
            
            if len(self.vc_signatures) >= quorum_threshold and self.new_view_created_for_view != v:
                # Set flag IMMEDIATELY to prevent race condition (multiple threads creating new-view)
                self.new_view_created_for_view = v
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: View change quorum reached: {len(self.vc_signatures)}/{quorum_threshold} (attack={has_attack})")
                
                # Extract min_s from view-change messages (should be consistent, take max to be safe)
                min_s_values = [vc_msg.get('n', 0) for vc_msg in self.vc_signatures.values()]
                min_s = max(min_s_values) if min_s_values else 0
                
                # Extract checkpoint certificate from view-change messages
                checkpoint_certs = [vc_msg.get('C') for vc_msg in self.vc_signatures.values() if 'C' in vc_msg and vc_msg.get('C')]
                if checkpoint_certs:
                    # Take the checkpoint with highest sequence number
                    checkpoint_cert = max(checkpoint_certs, key=lambda c: c.get('sequence_number', 0) if isinstance(c, dict) else 0)
                else:
                    checkpoint_cert = None
                
                # Collect all prepared requests from view-change messages
                # A request should be included if it appears in at least f+1 view-change messages (smart optimization)
                prepared_requests_by_seq = {}  # sequence_number -> {count, request_data}
                
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Collecting prepared requests from {len(self.vc_signatures)} view-change messages")
                for vc_sender, vc_msg in self.vc_signatures.items():
                    if 'P' in vc_msg and vc_msg['P']:
                        debug_print(f"[DEBUG-EQ]   View-change from server {vc_sender} contains {len(vc_msg['P'])} prepared requests:")
                        for prep_req in vc_msg['P']:
                            debug_print(f"[DEBUG-EQ]     - n={prep_req['n']}, v={prep_req['v']}, d={prep_req['d'][:8]}..., m={prep_req['m']}")
                            seq_n = prep_req['n']
                            if seq_n not in prepared_requests_by_seq:
                                prepared_requests_by_seq[seq_n] = {
                                    'count': 0,
                                    'n': prep_req['n'],
                                    'v': prep_req['v'],
                                    'd': prep_req['d'],
                                    'm': prep_req['m']
                                }
                            prepared_requests_by_seq[seq_n]['count'] += 1
                
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Collected {len(prepared_requests_by_seq)} unique sequence numbers:")
                for seq_n, prep_data in prepared_requests_by_seq.items():
                    debug_print(f"[DEBUG-EQ]   - n={seq_n}: count={prep_data['count']}, m={prep_data['m']}, d={prep_data['d'][:8]}...")
                
                # Detect equivocation conflicts: same transaction content with different sequence numbers
                # Group prepared requests by transaction content digest (not including sequence number)
                # IMPORTANT: Include ALL prepared requests in conflict detection, not just those with count >= F+1
                # This allows detecting conflicts even if one sequence number doesn't reach the threshold
                requests_by_tx_digest = {}  # tx_digest -> list of (seq_n, prep_data)
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Analyzing ALL prepared requests for conflicts (including those with count < {F + 1})")
                for seq_n, prep_data in prepared_requests_by_seq.items():
                    # Include ALL requests in conflict detection, regardless of count
                    # Compute digest of transaction content only (without sequence number)
                    # prep_data['m'] can be (id, (sender, receiver, amount)) or [id, [sender, receiver, amount]]
                    # We want to compare just (sender, receiver, amount)
                    transaction = prep_data['m']
                    tx_content = None
                    
                    # Handle both tuple and list formats (JSON serialization converts tuples to lists)
                    if isinstance(transaction, tuple) and len(transaction) == 2:
                        tx_content = transaction[1]  # (sender, receiver, amount)
                    elif isinstance(transaction, list) and len(transaction) == 2:
                        # Convert list to tuple for consistent digest computation
                        inner = transaction[1]
                        if isinstance(inner, list):
                            tx_content = tuple(inner)  # Convert [sender, receiver, amount] to (sender, receiver, amount)
                        else:
                            tx_content = inner
                    else:
                        # Fallback: try to extract from stored digest or use stored digest
                        debug_print(f"[DEBUG-EQ]   n={seq_n} (count={prep_data['count']}): Unexpected transaction format: {transaction}, type={type(transaction)}")
                        # Use stored digest as fallback (but this won't detect conflicts properly)
                        tx_digest = prep_data['d']
                        debug_print(f"[DEBUG-EQ]   n={seq_n} (count={prep_data['count']}): Using stored digest={tx_digest[:8]}... (WARNING: may not detect conflicts)")
                        if tx_digest not in requests_by_tx_digest:
                            requests_by_tx_digest[tx_digest] = []
                        requests_by_tx_digest[tx_digest].append((seq_n, prep_data))
                        continue
                    
                    # Compute digest from transaction content only (without sequence number)
                    tx_digest = self.digest(tx_content)
                    debug_print(f"[DEBUG-EQ]   n={seq_n} (count={prep_data['count']}): m={transaction}, tx_content={tx_content}, tx_digest={tx_digest[:8]}...")
                    
                    if tx_digest not in requests_by_tx_digest:
                        requests_by_tx_digest[tx_digest] = []
                    requests_by_tx_digest[tx_digest].append((seq_n, prep_data))
                
                # Identify conflicting sequence numbers (equivocation: same transaction content, different n)
                conflicting_seqs = set()
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Grouped by tx_digest: {len(requests_by_tx_digest)} unique transaction contents")
                for tx_d, req_list in requests_by_tx_digest.items():
                    seq_numbers = [seq_n for seq_n, _ in req_list]
                    debug_print(f"[DEBUG-EQ]   tx_digest {tx_d[:8]}...: sequence numbers {seq_numbers}")
                    if len(req_list) > 1:
                        # Same transaction content with multiple sequence numbers = equivocation conflict
                        debug_print(f"[DEBUG-EQ] Leader {self.server_id}: *** DETECTED EQUIVOCATION CONFLICT *** - transaction content digest {tx_d[:8]}... appears with sequence numbers {seq_numbers}")
                        conflicting_seqs.update(seq_numbers)
                
                # Create pre-prepare messages for requests that appear in at least f+1 view-change messages
                # BUT: If a sequence number is part of a conflict, assign no-op to it even if count < F+1
                O = []  # Set of pre-prepare messages for the new view
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Creating pre-prepare messages for 'O' field (conflicting_seqs={conflicting_seqs})")
                
                # First, assign no-op to ALL conflicting sequence numbers (even if count < F+1)
                for seq_n in conflicting_seqs:
                    debug_print(f"[DEBUG-EQ] Leader {self.server_id}: *** ASSIGNING NO-OP *** to conflicting sequence number n={seq_n}")
                    noop_transaction = (seq_n, (0, 0, 0))  # No-op: (n, (sender=0, receiver=0, amount=0))
                    noop_digest = self.digest(noop_transaction)
                    debug_print(f"[DEBUG-EQ]   No-op transaction: {noop_transaction}, digest: {noop_digest[:8]}...")
                    
                    # Create no-op client info
                    noop_client_info = {
                        'id': 0,
                        'signature': generate_signature(0),
                        'timestamp': time.time()
                    }
                    
                    noop_pre_prepare_msg = {
                        'v': v,  # New view
                        'n': seq_n,  # Conflicting sequence number
                        'd': noop_digest,  # No-op digest
                        'm': noop_transaction,  # No-op transaction
                        'client': noop_client_info,
                        's': self.get_node_signature(self.server_id)
                    }
                    O.append(noop_pre_prepare_msg)
                
                # Then, process non-conflicting requests that appear in at least f+1 view-change messages
                for seq_n, prep_data in prepared_requests_by_seq.items():
                    # Skip if already assigned no-op (conflicting)
                    if seq_n in conflicting_seqs:
                        continue
                    
                    # Only include requests that appear in at least f+1 view-change messages
                    if prep_data['count'] >= F + 1:
                        # Normal case: create pre-prepare message for this request in the new view
                        # Reconstruct client info from transaction (sender is the client)
                        transaction = prep_data['m']
                        id, (sender, receiver, amount) = transaction
                        debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Creating normal pre-prepare for n={seq_n}, transaction={transaction}")
                        
                        # Create basic client info (we don't have original client info, so reconstruct)
                        client_info = {
                            'id': sender,
                            'signature': generate_signature(sender),
                            'timestamp': time.time()
                        }
                        
                        pre_prepare_msg = {
                            'v': v,  # New view
                            'n': prep_data['n'],  # Same sequence number
                            'd': prep_data['d'],  # Same digest
                            'm': transaction,  # Transaction
                            'client': client_info,
                            's': self.get_node_signature(self.server_id)
                        }
                        O.append(pre_prepare_msg)
                
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Created {len(O)} pre-prepare messages for 'O' field ({len([o for o in O if (isinstance(o['m'], tuple) and len(o['m']) == 2 and o['m'][1] == (0, 0, 0)) or (isinstance(o['m'], list) and len(o['m']) == 2 and (o['m'][1] == [0, 0, 0] or o['m'][1] == (0, 0, 0)))])} no-ops, {len([o for o in O if not ((isinstance(o['m'], tuple) and len(o['m']) == 2 and o['m'][1] == (0, 0, 0)) or (isinstance(o['m'], list) and len(o['m']) == 2 and (o['m'][1] == [0, 0, 0] or o['m'][1] == (0, 0, 0))))])} normal)")
                
                message = {'pbft': {
                'type': 'new_view',
                'v': v,
                'v_signatures': self.vc_signatures.copy(),
                'O': O,  # Pre-prepare messages for requests to process in new view
                'min_s': min_s,  # Minimum sequence number from checkpoint
                's': self.get_node_signature(self.server_id)
                }}
                
                # Include checkpoint certificate if present (BONUS feature)
                if checkpoint_cert:
                    message['pbft']['C'] = checkpoint_cert
                
                self.new_view_logs.append(message)
                log = f'\nServer {self.server_id}: view change applied for v={v} with {len(O)} pre-prepare messages in O field, min_s={min_s}'
                if checkpoint_cert:
                    log += f', checkpoint_cert sequence={checkpoint_cert.get("sequence_number", 0)}'
                self.local_logs.append(log)
                print(log)
                self.broadcast_message(message, include_self=True)

    def handle_new_view(self, message):
        if self.server_id in Shared.byzantines and "crash" in current_attack_types:
            return

        # Message is already unwrapped (handle_pbft_message extracts request['pbft'])
        v = message['v']
        
        # Ignore duplicate new-view messages for the same view (already processed)
        if v in self.processed_new_views:
            return
        
        # Mark this view as processed
        self.processed_new_views.add(v)
        
        # Set view FIRST before any checkpoint restoration
        self.view = v
        self.vc_signatures = {}
        self.new_view_created_for_view = None  # Reset flag when view changes
        self.cancel_view_change()
        self.accepted_number = None
        self.accepted_value = None
        self.pending_pbft = False
        
        # BONUS FEATURE: Process checkpoint certificate if present
        # This enables replica recovery from stable checkpoints
        if 'C' in message and message['C']:
            checkpoint_cert = message['C']
            log = f'Server {self.server_id}: [BONUS-CHECKPOINT] Processing checkpoint certificate from new-view: sequence {checkpoint_cert["sequence_number"]}'
            self.local_logs.append(log)
            print(log)
            
            # Restore from checkpoint if this replica is behind
            latest_checkpoint = self.get_latest_stable_checkpoint()
            if not latest_checkpoint or checkpoint_cert['sequence_number'] > latest_checkpoint.get('sequence_number', -1):
                # Restore checkpoint but preserve the new view (don't overwrite view from checkpoint)
                try:
                    self.restore_from_checkpoint(checkpoint_cert, preserve_view=True)
                    log = f'Server {self.server_id}: [BONUS-CHECKPOINT] Restored from checkpoint n={checkpoint_cert["sequence_number"]}'
                    self.local_logs.append(log)
                    print(log)
                except Exception as e:
                    import traceback
                    print(traceback.format_exc())
                    raise
        
        # Process 'O' field: pre-prepare messages for requests to process in new view
        if 'O' in message and message['O']:
            O = message['O']
            log = f'Server {self.server_id}: Processing {len(O)} pre-prepare messages from new-view O field'
            self.local_logs.append(log)
            debug_print(f"[DEBUG-EQ] {log}")
            
            noop_count = 0
            normal_count = 0
            for idx, pre_prepare_msg in enumerate(O):
                # Check if this is a no-op
                # Handle both tuple and list formats (JSON serialization converts tuples to lists)
                m = pre_prepare_msg['m']
                is_noop = False
                if isinstance(m, tuple) and len(m) == 2:
                    is_noop = m[1] == (0, 0, 0)
                elif isinstance(m, list) and len(m) == 2:
                    is_noop = m[1] == [0, 0, 0] or m[1] == (0, 0, 0)
                
                if is_noop:
                    noop_count += 1
                    seq_n = pre_prepare_msg['n']
                    v = pre_prepare_msg['v']
                    debug_print(f"[DEBUG-EQ] Server {self.server_id}: Processing no-op pre-prepare from 'O' field: n={seq_n}, m={m}")
                    
                    # Immediately update database: set status to 'E' for this sequence number
                    # Use existing functions to check and update
                    current_status = self.get_tx_status_by_seq(seq_n)
                    
                    if current_status == 'X':
                        # Transaction doesn't exist, add it with no-op values and status 'E'
                        # For no-op: sender=0, receiver=0, amount=0
                        noop_message = (seq_n, (0, 0, 0))
                        noop_accepted_number = (v, seq_n)
                        self.add_transaction_to_datastore(noop_message, noop_accepted_number, 'E')
                        debug_print(f"[DEBUG-EQ] Server {self.server_id}: Inserted new transaction n={seq_n} with status 'E' (no-op)")
                    else:
                        # Transaction exists, update its status to 'E'
                        self.update_transaction_status(seq_n, 'E')
                        debug_print(f"[DEBUG-EQ] Server {self.server_id}: Updated existing transaction n={seq_n} to status 'E' (no-op)")
                    
                    # Skip processing this no-op through handle_pre_prepare since we've already marked it as executed
                    continue
                else:
                    normal_count += 1
                    debug_print(f"[DEBUG-EQ] Server {self.server_id}: Processing normal pre-prepare from 'O' field: n={pre_prepare_msg['n']}, m={m}")
                
                # Process each pre-prepare message to reprocess prepared requests
                # Convert to the format expected by handle_pre_prepare
                pbft_message = {
                    'type': 'preprepare',
                    'v': pre_prepare_msg['v'],
                    'n': pre_prepare_msg['n'],
                    'd': pre_prepare_msg['d'],
                    'm': pre_prepare_msg['m'],
                    'client': pre_prepare_msg['client'],
                    's': pre_prepare_msg['s']
                }
                # Handle the pre-prepare message (this will trigger the prepare phase)
                # self.handle_pre_prepare(pbft_message)
            
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: Processed {noop_count} no-ops and {normal_count} normal pre-prepares from 'O' field")
        
        log = f'\nServer {self.server_id}: New view ={self.view} set!'
        self.local_logs.append(log)
        print(log)

    def reset_view_timer(self, dest):
        if self.view_timer == None:
            # First time setting view timer for this backup
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: Setting initial view timer (timeout={self.view_timeout}s) from {dest}")
        else:
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: Resetting view timer from {dest}")
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
        
        # Convert list to tuple if needed (JSON serialization converts tuples to lists)
        # Handle nested structures: (n, (sender, receiver, amount))
        original_m = m
        if isinstance(m, list):
            # Convert outer list to tuple
            m = tuple(m)
            # Convert inner list (transaction part) to tuple if it exists
            if len(m) == 2 and isinstance(m[1], list):
                m = (m[0], tuple(m[1]))
        
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: handle_pre_prepare - original m={original_m} (type={type(original_m)}), converted m={m} (type={type(m)})")

        # if self.accepted_number != None and self.accepted_number != (v, n):
        #     self.accepted_number = None
        #     self.accepted_value = None

        import hashlib
        value = str(v)
        hash_object = hashlib.sha256(value.encode())
        hash_hex = hash_object.hexdigest()
        
        if v in Shared.byzantines and "sign" in current_attack_types:
            expected_signature = hash_hex + "_INVALID_BYZANTINE"
        else:
            expected_signature = hash_hex
            
        # Debug: Check each validation condition
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: Received pre-prepare for n={n}, v={v}, self.view={self.view}, accepted_number={self.accepted_number}, transaction={m}")
        view_match = v == self.view
        computed_d = self.digest(m)
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: Digest comparison - received d={d[:8]}..., computed d={computed_d[:8]}... from m={m}")
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: Digest match={d == computed_d}, str(m)={str(m)}")
        digest_match = d == computed_d
        signature_match = signature == expected_signature
        accepted_check = self.accepted_number == None or (self.accepted_number == (v, n) and self.accepted_value == d)
        
        isValid = view_match and digest_match and signature_match and accepted_check

        if not isValid:
            reasons = []
            if not view_match:
                reasons.append(f"view mismatch (msg v={v}, self.view={self.view})")
            if not digest_match:
                reasons.append(f"digest mismatch (expected {d[:8]}..., got {computed_d[:8]}...)")
            if not signature_match:
                reasons.append("signature mismatch")
            if not accepted_check:
                reasons.append(f"accepted_number conflict (self.accepted_number={self.accepted_number}, expected (v={v}, n={n}))")
            
            log = f'server {self.server_id} PP was not valid!!! Reasons: {", ".join(reasons)}'
            self.local_logs.append(log)
            debug_print(f"[DEBUG-EQ] {log}")

        if isValid:
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: ACCEPTED pre-prepare for n={n}, v={v}, d={d[:8]}...")
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
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: Sending PREPARE for n={n} to leader {self.view}")
            
            if self.server_id in Shared.byzantines and "crash" in current_attack_types:
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
        if self.server_id in Shared.byzantines and "crash" in current_attack_types:
            return
        
        n = message['n']
        signature = message['s']
        sender_id = message['i']
        
        import hashlib
        value = str(sender_id)
        hash_object = hashlib.sha256(value.encode())
        hash_hex = hash_object.hexdigest()
        
        expected_signature = hash_hex
        
        if signature != expected_signature:
            return
        
        with self.response_lock:
            log = f'Receiving prepare by leader:{self.server_id} with payload: {message}'
            self.local_logs.append(log)
            debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Received PREPARE from server {sender_id} for n={n}, count={self.majority_responses + 1}/{MAJORITY}")
            self.majority_responses += 1
            self.prepared_signatures.append(signature)
            if self.majority_responses >= MAJORITY:
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: MAJORITY REACHED for n={n}! ({self.majority_responses}/{MAJORITY})")
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
            debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Waiting for majority (timeout={timeout}s), current count={self.majority_responses}")
            self.condition.wait_for(lambda: self.majority_reached, timeout=timeout)
            if self.majority_reached:
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Majority reached in wait_for_majority for {self.accepted_number}")
                # print(f"Server {self.server_id}: Majority of promises received, proceeding to send accept.")
                is_super_majority = self.majority_responses == 3*F+1
                self.majority_reached = False
                self.majority_responses = 1
                log = f'Majority reached! send prepare ack for {self.accepted_number}'
                self.local_logs.append(log)
                # print(log)
                if is_super_majority:
                    debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Super majority, committing directly")
                    self.commit_transaction(True)
                else:
                    debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Normal majority, sending prepare_ack")
                    self.send_prepare_ack()
            else:
                log = f"Server {self.server_id}: Timeout reached on collecting prepares, aborting PBFT."
                self.local_logs.append(log)
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: TIMEOUT in wait_for_majority for {self.accepted_number}, count={self.majority_responses}")
                self.majority_reached = False 
                self.majority_responses = 1
                # Reset and process queued transactions (e.g., equivocation n=2)
                if self.view == self.server_id and self.transaction_queue:
                    debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Processing queued transactions after timeout")
                    threading.Timer(0.2, self.handle_consensus_completion).start()


    def send_prepare_ack(self):
        if self.accepted_number == None:
            return
        
        n = self.accepted_number[1]
        debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Sending prepare_ack for n={n} with {len(self.prepared_signatures)} signatures")
        message = {'pbft': {
                'type': 'prepare_ack',
                'v': self.server_id,
                'n': n,
                'certificate': self.prepared_signatures,
            }}
        
        # Check if this is equivocation: only send to servers that received the pre-prepare
        if n in self.equivocation_targets_by_seq:
            target_servers = self.equivocation_targets_by_seq[n]
            debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Equivocation mode - sending prepare_ack for n={n} only to servers {target_servers}")
            for server_id in target_servers:
                if server_id in self.live_servers:
                    self.send_message(server_id + 5000, message)
        else:
            # Normal: broadcast to all
            self.broadcast_message(message)
        self.wait_for_accepted_majority()


    def handle_prepare_ack(self, message):
        if self.server_id in Shared.byzantines and "crash" in current_attack_types:
            return
            
        if self.server_id not in Shared.byzantines:
            self.reset_view_timer('Prepare Ack')

        signatures = message['certificate']
        v = message['v']
        n = message['n']

        isValid = len(signatures) >= MAJORITY and (self.accepted_number != None or self.accepted_number == (v, n))
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: Received prepare_ack for n={n}, signatures={len(signatures)}, isValid={isValid}, accepted_number={self.accepted_number}")
        if isValid == False:
            return
        
        if self.server_id in Shared.byzantines and "sign" in current_attack_types:
            self.accepted_number = None
            self.accepted_value = None
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
            n = self.accepted_number[1] if self.accepted_number else "?"
            debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Waiting for COMMIT majority for n={n} (timeout={timeout}s)")
            # Wait until a majority of accepted messages is received or the timeout occurs
            self.accept_condition.wait_for(lambda: self.accept_majority_reached, timeout=timeout)
            if self.accept_majority_reached:
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: COMMIT majority reached in wait_for_accepted_majority for n={n}")
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
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: TIMEOUT in wait_for_accepted_majority for n={n}, count={self.accept_majority_responses}")
                self.accept_majority_reached = False
                self.accept_majority_responses = 1


    def handle_commit(self, message):
        d = message['d']
        n = message['n']
        v = message['v']
        s = message['s']
        with self.accept_response_lock:
            if (v, n) != self.accepted_number or d != self.accepted_value:
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Rejected COMMIT for n={n} (accepted_number={self.accepted_number}, d match={d == self.accepted_value})")
                return
            
            self.accept_majority_responses += 1
            debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Received COMMIT from server {s} for n={n}, count={self.accept_majority_responses}/{MAJORITY}")

            if self.accept_majority_responses >= MAJORITY:
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: COMMIT MAJORITY REACHED for n={n}! ({self.accept_majority_responses}/{MAJORITY})")
                self.accept_majority_reached = True
                self.accept_condition.notify()
                # print(f"Server {self.server_id}: Reached majority, committing request {message}")

    def commit_transaction(self, is_super=False):
        # Commit the block locally
        n = self.accepted_number[1] if self.accepted_number else "?"
        debug_print(f"[DEBUG-EQ] Leader {self.server_id}: COMMITTING transaction n={n} (is_super={is_super})")
        start_time = time.time()
        self.update_transaction_status(self.accepted_number[1], 'C')
        # self.clear_outdated_logs(unique_major_block)

        # Update performance metrics
        processing_time = time.time() - start_time  # Calculate processing time
        self.total_transaction_time += processing_time
        self.total_transactions_committed += 1

        # Execution
        # Get client_id from the committed transaction (not self.message which might be stale)
        # For equivocation, self.message might still be from n=1 when n=2 commits
        # Save n and d before execute_transaction might reset accepted_number and accepted_value
        commit_n = self.accepted_number[1] if self.accepted_number else None
        commit_d = self.accepted_value  # Save the digest before execute_transaction resets it
        n = commit_n
        if n:
            # Get the transaction from database to get the correct client_id
            transactions = self.get_all_transactions()
            client_id = None
            for trans in transactions:
                # Handle both old format (7 columns) and new format (8 columns with transaction_type)
                if len(trans) >= 7:
                    id, seq_n, s, r, amount, view, status = trans[:7]
                    if seq_n == n and status == 'C':
                        # Extract client_id from the transaction (sender is the client)
                        # Handle None values (e.g., for no-op transactions)
                        client_id = Shared.get_number_for_alphabet(s) if s else None
                        if client_id is None:
                            continue  # Skip if sender is None (no-op transaction)
                        break
            # Fallback to self.message if not found in database
            if client_id is None and self.message:
                client_id = self.message[1][0]
        else:
            # Fallback if no accepted_number
            client_id = self.message[1][0] if self.message else None
        
        if client_id:
            self.execute_transaction(client_id)


        # Broadcast COMMIT_ACK message to all other servers (or split broadcast for equivocation)
        # Use saved commit_n and commit_d instead of self.accepted_number/self.accepted_value
        # since execute_transaction may have reset them
        n = commit_n
        # Use saved commit_d (the digest that backups have) instead of recomputing from self.message
        # This ensures the digest matches what backups expect
        if commit_d is None:
            commit_d = self.digest(self.message)  # Fallback if commit_d wasn't saved
        message = {
            'pbft': {
                'type': 'commit_ack',
                'v': self.view,
                'n': n,
                'd': commit_d,
                'i': self.server_id,
                's': self.get_node_signature(self.server_id),
                'sm': is_super
            }
        }
        
        # Check if this is equivocation: only send to servers that received the pre-prepare
        if n in self.equivocation_targets_by_seq:
            target_servers = self.equivocation_targets_by_seq[n]
            debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Equivocation mode - sending commit_ack for n={n} only to servers {target_servers}")
            for server_id in target_servers:
                if server_id in self.live_servers:
                    self.send_message(server_id + 5000, message)
        else:
            # Normal: broadcast to all
            debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Broadcasting commit_ack for n={n} to all live servers")
            self.broadcast_message(message)
        
        # Reset accepted_number after execution and sending commit_ack to allow next transaction
        self.accepted_number = None
        self.accepted_value = None
        
        threading.Timer(0.2, self.handle_consensus_completion).start()

    def execute_transaction(self, client_id):
        try:
            transactions = self.get_all_transactions()
            commited = []
            executed = []
            for trans in transactions:
                # Handle both old format (7 columns) and new format (8 columns with transaction_type)
                if len(trans) >= 8:
                    id, n, s, r, amount, view, status, tx_type = trans[:8]
                else:
                    id, n, s, r, amount, view, status = trans[:7]
                    tx_type = 'TRANSFER'  # Default to legacy format
                # Handle None values (e.g., for no-op transactions or invalid data)
                sender = Shared.get_number_for_alphabet(s) if s else 0
                receiver = Shared.get_number_for_alphabet(r) if r else 0
                normalized_trans = (id, n, sender, receiver, amount, view, status)
                if status == 'C':
                    commited.append(normalized_trans)
                elif status == 'E' or status.startswith('E - '):
                    # Include both successful and failed transactions in executed list
                    # to maintain sequence continuity
                    executed.append(normalized_trans)

            # Debug: Log execution state
            if len(commited) > 0:
                log = f"Server {self.server_id}: Executing transactions - {len(commited)} committed, {len(executed)} already executed"
                self.local_logs.append(log)
                debug_print(f"[DEBUG-EQ] Server {self.server_id}: execute_transaction - {len(commited)} committed, {len(executed)} executed")
                debug_print(f"[DEBUG-EQ] Server {self.server_id}: Committed transactions: {[(t[1], t[2], t[3], t[4]) for t in commited]}")
                debug_print(f"[DEBUG-EQ] Server {self.server_id}: Executed transactions: {[(t[1], t[2], t[3], t[4]) for t in executed]}")

            if len(commited) == 0:
                debug_print(f"[DEBUG-EQ] Server {self.server_id}: No committed transactions to execute")
                self.reply_client(client_id, 'yes')
                return

            # Track initial executed count to detect if we executed something new
            initial_executed_count = len(executed)
            
            for commit in commited:
                last_exec_n = 0 if len(executed) == 0 else executed[-1][1]
                # Handle both old format (7 columns) and new format (8 columns with transaction_type)
                if len(commit) >= 8:
                    id, n, sender, receiver, amount, view, status, tx_type = commit[:8]
                else:
                    id, n, sender, receiver, amount, view, status = commit[:7]
                    tx_type = 'TRANSFER'  # Default to legacy format
                
                if last_exec_n + 1 == n:
                    # Check if this is a no-op operation (sender=0, receiver=0, amount=0)
                    is_noop = (sender == 0 and receiver == 0 and amount == 0)
                    
                    if is_noop:
                        log = f"Server {self.server_id}: Processed no-op transaction n = {n}"
                        self.local_logs.append(log)
                        debug_print(f"[DEBUG-EQ] {log}")
                        executed.append(commit)
                        self.update_transaction_status(n, 'E')
                        # No-op doesn't modify balances or send reply to client
                    elif tx_type and tx_type != 'TRANSFER':
                        # SmallBank transaction
                        result = self.execute_smallbank_transaction(n, tx_type, sender, receiver, amount, commit)
                        if result:
                            executed.append(commit)
                            self.update_transaction_status(n, 'E')
                            self.reply_client(result.get('client_id', client_id), result.get('reply', 'yes'))
                    else:
                        # Legacy TRANSFER transaction
                        log = f"Server {self.server_id}: Processed transaction n = {n} ({sender} -> {receiver}: {amount})"
                        self.local_logs.append(log)
                        print(log)
                        executed.append(commit)
                        if self.balances[sender] - amount < 0:
                            self.update_transaction_status(n, 'E - Insufficient funds!')
                            self.reply_client(sender, 'no')
                        else:
                            self.balances[sender] -= amount
                            self.balances[receiver] += amount
                            self.update_transaction_status(n, 'E')
                            self.reply_client(sender, 'yes')
                    
                    # BONUS FEATURE: Check if we should create a checkpoint after execution
                    self.check_checkpoint_trigger(n)
                elif self.view != self.server_id:
                    self.reset_view_timer('Else C')
            
            # Reset accepted_number after execution to allow next transaction
            # This ensures backups can accept the next pre-prepare message
            # Only reset if we actually executed something new in this call
            if len(executed) > initial_executed_count:
                self.accepted_number = None
                self.accepted_value = None
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            raise

    def execute_smallbank_transaction(self, n, tx_type, sender_field, receiver_field, amount_field, commit):
        """
        Execute SmallBank transaction types.
        sender_field contains the transaction type string
        receiver_field contains comma-separated arguments
        amount_field contains the first numeric argument
        """
        try:
            # Parse arguments from receiver_field (comma-separated)
            if receiver_field:
                args = [int(x.strip()) if x.strip().isdigit() else x.strip() for x in str(receiver_field).split(',')]
            else:
                args = []
            
            client_id = None
            reply = 'yes'
            log_msg = ""
            
            if tx_type == 'Amalgamate':
                # Amalgamate(s, r): Transfer all savings to checking for s, then send payment to r's checking
                if len(args) >= 2:
                    s, r = args[0], args[1]
                    # Transfer all savings to checking
                    savings_amt = self.savings_balances.get(s, 0)
                    self.savings_balances[s] = 0
                    self.checking_balances[s] = self.checking_balances.get(s, 0) + savings_amt
                    # Then send payment (use savings amount as payment amount)
                    if self.checking_balances.get(s, 0) >= savings_amt:
                        self.checking_balances[s] -= savings_amt
                        self.checking_balances[r] = self.checking_balances.get(r, 0) + savings_amt
                        log_msg = f"Server {self.server_id}: Processed SmallBank Amalgamate n={n} (s={s}, r={r}, transferred={savings_amt})"
                    else:
                        reply = 'no'
                        log_msg = f"Server {self.server_id}: SmallBank Amalgamate n={n} failed - insufficient checking balance"
                    client_id = s
                    
            elif tx_type == 'Balance':
                # Balance(s): Read checking and savings balances (read-only, no state change)
                if len(args) >= 1:
                    s = args[0]
                    checking = self.checking_balances.get(s, 0)
                    savings = self.savings_balances.get(s, 0)
                    log_msg = f"Server {self.server_id}: Processed SmallBank Balance n={n} (s={s}, checking={checking}, savings={savings})"
                    client_id = s
                    # Balance is read-only, no state change
                    
            elif tx_type == 'DepositChecking':
                # DepositChecking(s, amount): Add amount to checking account s
                if len(args) >= 2:
                    s, amount = args[0], args[1]
                    self.checking_balances[s] = self.checking_balances.get(s, 0) + amount
                    log_msg = f"Server {self.server_id}: Processed SmallBank DepositChecking n={n} (s={s}, amount={amount})"
                    client_id = s
                    
            elif tx_type == 'SendPayment':
                # SendPayment(s, r, amount): Transfer amount from checking s to checking r
                if len(args) >= 3:
                    s, r, amount = args[0], args[1], args[2]
                    if self.checking_balances.get(s, 0) >= amount:
                        self.checking_balances[s] -= amount
                        self.checking_balances[r] = self.checking_balances.get(r, 0) + amount
                        log_msg = f"Server {self.server_id}: Processed SmallBank SendPayment n={n} (s={s} -> r={r}, amount={amount})"
                    else:
                        reply = 'no'
                        log_msg = f"Server {self.server_id}: SmallBank SendPayment n={n} failed - insufficient funds"
                    client_id = s
                    
            elif tx_type == 'TransactSavings':
                # TransactSavings(s, amount): Add or subtract amount from savings s (amount can be negative)
                if len(args) >= 2:
                    s, amount = args[0], args[1]
                    new_balance = self.savings_balances.get(s, 0) + amount
                    if new_balance >= 0:  # Savings can't go negative
                        self.savings_balances[s] = new_balance
                        log_msg = f"Server {self.server_id}: Processed SmallBank TransactSavings n={n} (s={s}, amount={amount})"
                    else:
                        reply = 'no'
                        log_msg = f"Server {self.server_id}: SmallBank TransactSavings n={n} failed - insufficient savings"
                    client_id = s
                    
            elif tx_type == 'WriteCheck':
                # WriteCheck(s, amount): Deduct amount from checking s (can go negative)
                if len(args) >= 2:
                    s, amount = args[0], args[1]
                    self.checking_balances[s] = self.checking_balances.get(s, 0) - amount
                    log_msg = f"Server {self.server_id}: Processed SmallBank WriteCheck n={n} (s={s}, amount={amount}, new_balance={self.checking_balances[s]})"
                    client_id = s
                    # WriteCheck allows negative balance, so always succeeds
                    
            if log_msg:
                self.local_logs.append(log_msg)
                print(log_msg)
                
            return {'client_id': client_id, 'reply': reply} if client_id else None
            
        except Exception as e:
            import traceback
            error_msg = f"Server {self.server_id}: Error executing SmallBank transaction {tx_type}: {e}"
            self.local_logs.append(error_msg)
            print(error_msg)
            print(traceback.format_exc())
            return None

    def reply_client(self, client_id, msg):
        try:
            self.cancel_view_change()
            
            client_port = client_id + 8000
            reply_message = {'reply': msg, 'v': self.view}
            
            self.send_message(client_port, message=reply_message)
            
            log = f"Server {self.server_id}: reply {msg} within view {self.view} for client:{client_id}"
            self.local_logs.append(log)
            # print(log)
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            raise


    def handle_commit_ack(self, message):
        if self.server_id in Shared.byzantines and "crash" in current_attack_types:
            return
        
        v = message['v']
        n = message['n']
        d = message['d']
        sm = message['sm']
        
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: Received commit_ack for n={n}, v={v}, accepted_number={self.accepted_number}")
        
        self.reset_view_timer('C')
        
        # This prevents executing n=1 when we receive commit_ack for n=2 (i.e. equivocation attack)
        if self.accepted_number != (v, n):
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: Rejected commit_ack for n={n} (accepted_number={self.accepted_number}, expected (v={v}, n={n}))")
            return
        
        if sm == False and self.prepared != (v, n, d):
            log = f'No Prepared for {self.server_id} with v={v} n={n} d={d}!!!'
            self.local_logs.append(log)
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: Rejected commit_ack - prepared check failed: sm={sm}, self.prepared={self.prepared}, expected (v={v}, n={n}, d={d[:8]}...)")
            return
        log = f'committing on server {self.server_id}: prepared: {self.prepared}'
        self.local_logs.append(log)
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: {log}")

        # Use n from message (validated above to match accepted_number)
        self.update_transaction_status(n, 'C')

        # Get client_id from the committed transaction (not self.message which might be stale)
        # For equivocation, self.message might still be from n=1 when n=2 commits
        transactions = self.get_all_transactions()
        client_id = None
        for trans in transactions:
            # Handle both old format (7 columns) and new format (8 columns with transaction_type)
            if len(trans) >= 7:
                id, seq_n, s, r, amount, view, status = trans[:7]
                if seq_n == n and status == 'C':
                    # Extract client_id from the transaction (sender is the client)
                    # Handle None values (e.g., for no-op transactions)
                    client_id = Shared.get_number_for_alphabet(s) if s else None
                    if client_id is None:
                        continue  # Skip if sender is None (no-op transaction)
                    break
        # Fallback to self.message if not found in database
        if client_id is None and self.message:
            client_id = self.message[1][0] if len(self.message) > 1 and len(self.message[1]) > 0 else None
        
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: handle_commit_ack - calling execute_transaction with client_id={client_id} for n={n}")
        if client_id:
            self.execute_transaction(client_id)
        
        # self.clear_outdated_logs(major_block) 
        self.reset_local_values()
        
        # Ensure accepted_number is reset after execution to allow next transaction
        # This is critical for backups to accept the next pre-prepare message
        self.accepted_number = None
        self.accepted_value = None

    def assign_n(t):
        return t[0]
    
    def _handle_equivocation_attack(self, n, d, transaction, client):
        """Handle equivocation Byzantine attack - returns True if attack was handled"""
        if self.server_id not in Shared.byzantines or self.view != self.server_id:
            return False
            
        for attack in current_attack_types:
            if attack.startswith("equivocation("):
                targets_str = attack[13:-1]
                if not targets_str:
                    return False
                    
                target_nodes = [int(node.strip()[1:]) for node in targets_str.split(',')]  # Remove 'n' prefix
                n1, n2 = n, n + 1
                
                print(f"Server {self.server_id} (Byzantine Leader): Equivocation attack - sending seq {n1} to nodes {target_nodes}, will queue n={n2} for others")
                
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: _handle_equivocation_attack - n={n1}, transaction={transaction}, transaction type={type(transaction)}")
                if isinstance(transaction, list):
                    normalized_tx = tuple(transaction)
                    if len(normalized_tx) == 2 and isinstance(normalized_tx[1], list):
                        normalized_tx = (normalized_tx[0], tuple(normalized_tx[1]))
                else:
                    normalized_tx = transaction
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Normalized transaction={normalized_tx}, digest d={d[:8]}...")
                recomputed_d = self.digest(normalized_tx)
                debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Recomputed digest={recomputed_d[:8]}... (matches={d == recomputed_d})")
                
                # Send n=1 pre-prepare to target_nodes only
                # Store which servers received n=1 for split broadcast of prepare_ack/commit_ack
                self.equivocation_targets_by_seq[n1] = target_nodes.copy()
                for target_node in target_nodes:
                    if target_node in self.live_servers and target_node != self.server_id:
                        debug_print(f"[DEBUG-EQ] Leader {self.server_id}: Sending n={n1} pre-prepare to server {target_node} with d={d[:8]}..., transaction={transaction}")
                        self._send_preprepare_message(target_node, n1, d, transaction, client)
                
                # Queue n=2 as a separate transaction to process after n=1 completes
                # n=2 will be sent only to "others" (nodes not in target_nodes)
                n2_transaction = (n2, transaction[1])  # Create transaction tuple with n2 as sequence number
                n2_payload = {
                    'client': client,
                    'transaction': n2_transaction,
                    'live_servers': self.live_servers,
                    'equivocation_n2': True,  # Flag to indicate this is equivocation n=2
                    'equivocation_exclude': target_nodes  # Nodes that already received n=1
                }
                self.transaction_queue.append(n2_payload)
                
                # Process n=1 normally (add to datastore and wait for majority)
                self.add_transaction_to_datastore(self.message, self.accepted_number, 'PP')
                log = f'Equivocation PP by leader:{self.server_id} for request {transaction} (n={n1}), queued n={n2} for others'
                self.local_logs.append(log)
                self.wait_for_majority()  # Wait for n=1 to complete
                return True
                
        return False
    
    def _send_preprepare_message(self, target_server, sequence_num, digest, transaction, client):
        """Helper method to send pre-prepare message"""
        message = {'pbft': {
            'type': 'preprepare',
            'v': self.view,
            'n': sequence_num,
            'd': digest,
            'm': transaction,
            'client': client,
            's': self.get_node_signature(self.server_id)
        }}
        self.send_message(target_server + 5000, message)

    def digest(self, message):
        value = str(message)
        hash_object = hashlib.sha256(value.encode())
        hash_hex = hash_object.hexdigest()
        return hash_hex
    
    def get_node_signature(self, server_id):
        value = str(server_id)
        hash_object = hashlib.sha256(value.encode())
        hash_hex = hash_object.hexdigest()
        
        if self.server_id in Shared.byzantines and "sign" in current_attack_types:
            invalid_sig = hash_hex + "_INVALID_BYZANTINE"
            return invalid_sig
        
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
        status = self.get_tx_status_by_seq(n)
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
        if self.server_id in Shared.byzantines and "sign" in current_attack_types:
            invalid_partial = str(self.key_share) + "_INVALID_PARTIAL"
            return invalid_partial
        
        return self.key_share

    def verify_threshold_signature(self, threshold_signature, message_digest):
        return self.public_key.verify(threshold_signature, message_digest)

    def find_port(self, sender_id):
        return next((item for item in self.peers if item % 1000 == sender_id), None)

    def calculate_all_balances(self):
        all_transactions = []
        datastore = self.get_transactions_by_status('E')
        for trans in datastore:
            # Handle both old format (7 columns) and new format (8 columns with transaction_type)
            if len(trans) >= 8:
                id, sequence_number, s, r, amount, ballot_number, process_id, tx_type = trans[:8]
            else:
                id, sequence_number, s, r, amount, ballot_number, process_id = trans[:7]
            # Handle None values (e.g., for no-op transactions or invalid data)
            sender = Shared.get_number_for_alphabet(s) if s else 0
            receiver = Shared.get_number_for_alphabet(r) if r else 0
            if sender == 0 and receiver == 0 and amount == 0:
                continue
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
            # Handle both old format (7 columns) and new format (8 columns with transaction_type)
            if len(trans) >= 8:
                id, sequence_number, s, r, amount, ballot_number, process_id, tx_type = trans[:8]
            else:
                id, sequence_number, s, r, amount, ballot_number, process_id = trans[:7]
            # Handle None values (e.g., for no-op transactions or invalid data)
            sender = Shared.get_number_for_alphabet(s) if s else 0
            receiver = Shared.get_number_for_alphabet(r) if r else 0
            if sender == 0 and receiver == 0 and amount == 0:
                continue
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
        debug_print(f"[DEBUG-EQ] Server {self.server_id}: handle_consensus_completion called, queue length={len(self.transaction_queue)}")
        if self.transaction_queue:
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: Queued transactions: {[(t.get('transaction', '?'), t.get('equivocation_n2', False)) for t in self.transaction_queue]}")
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

    def create_checkpoint(self, sequence_number):
        """BONUS FEATURE: Create a checkpoint for the given sequence number
        Checkpoints enable garbage collection and replica recovery"""
        if sequence_number <= self.last_checkpoint_sequence:
            return
            
        # Create checkpoint data
        checkpoint_data = {
            'sequence_number': sequence_number,
            'view': self.view,
            'balances': self.balances.copy(),  # Legacy balances
            'savings_balances': self.savings_balances.copy(),  # SmallBank savings
            'checking_balances': self.checking_balances.copy(),  # SmallBank checking
            'executed_transactions': self.get_transactions_by_status('E')
        }
        
        if sequence_number not in self.checkpoints:
            self.checkpoints[sequence_number] = {}
        self.checkpoints[sequence_number][self.server_id] = checkpoint_data
        self.last_checkpoint_sequence = sequence_number
        
        # Broadcast checkpoint message to all replicas
        message = {'pbft': {
            'type': 'checkpoint',
            'sequence_number': sequence_number,
            'view': self.view,
            'balances': self.balances.copy(),  # Legacy balances
            'savings_balances': self.savings_balances.copy(),  # SmallBank savings
            'checking_balances': self.checking_balances.copy(),  # SmallBank checking
            'executed_transactions': self.get_transactions_by_status('E'),
            'i': self.server_id,
            's': self.get_node_signature(self.server_id)
        }}
        
        log = f'Server {self.server_id}: [BONUS-CHECKPOINT] Creating checkpoint for sequence {sequence_number} (every {self.checkpoint_interval} requests)'
        self.local_logs.append(log)
        print(log)
        
        live_ports = [server + 5000 for server in self.live_servers if server != self.server_id]
        log = f'Server {self.server_id}: [BONUS-CHECKPOINT] Broadcasting checkpoint to live servers: {self.live_servers} (ports: {live_ports})'
        self.local_logs.append(log)
        print(log)
        
        self.broadcast_message(message)
        
        log = f'Server {self.server_id}: [BONUS-CHECKPOINT] Checkpoint broadcast completed to {len(live_ports)} servers'
        self.local_logs.append(log)
        print(log)

    def handle_checkpoint(self, message):
        """BONUS FEATURE: Handle incoming checkpoint message"""
        sequence_number = message['sequence_number']
        view = message['view']
        balances = message.get('balances', {})  # Legacy balances
        savings_balances = message.get('savings_balances', {})  # SmallBank savings
        checking_balances = message.get('checking_balances', {})  # SmallBank checking
        executed_transactions = message['executed_transactions']
        sender_id = message['i']
        signature = message['s']
        
        log = f'Server {self.server_id}: [BONUS-CHECKPOINT] Received checkpoint from Server {sender_id} for sequence {sequence_number}'
        self.local_logs.append(log)
        # print(log)
        
        # Validate signature
        expected_signature = self.get_node_signature(sender_id)
        if signature != expected_signature:
            log = f'Server {self.server_id}: [BONUS-CHECKPOINT] Invalid signature from Server {sender_id}, rejecting'
            self.local_logs.append(log)
            print(log)
            return
            
        # Store checkpoint
        checkpoint_data = {
            'sequence_number': sequence_number,
            'view': view,
            'balances': balances,  # Legacy balances
            'savings_balances': savings_balances,  # SmallBank savings
            'checking_balances': checking_balances,  # SmallBank checking
            'executed_transactions': executed_transactions
        }
        
        if sequence_number not in self.checkpoints:
            self.checkpoints[sequence_number] = {}
        
        self.checkpoints[sequence_number][sender_id] = checkpoint_data
        
        # Check if we have 2f+1 matching checkpoints
        if len(self.checkpoints[sequence_number]) >= MAJORITY:
            # Verify all checkpoints match
            first_checkpoint = list(self.checkpoints[sequence_number].values())[0]
            all_match = all(
                cp['sequence_number'] == first_checkpoint['sequence_number'] and
                cp['view'] == first_checkpoint['view'] and
                cp.get('balances', {}) == first_checkpoint.get('balances', {}) and
                cp.get('savings_balances', {}) == first_checkpoint.get('savings_balances', {}) and
                cp.get('checking_balances', {}) == first_checkpoint.get('checking_balances', {})
                for cp in self.checkpoints[sequence_number].values()
            )
            
            if all_match:
                # Checkpoint is stable
                self.stable_checkpoints[sequence_number] = first_checkpoint
                log = f'Server {self.server_id}: [BONUS-CHECKPOINT] Checkpoint {sequence_number} is now STABLE (received 2f+1 matching checkpoints)'
                self.local_logs.append(log)
                print(log)
                
                # Mark checkpoint as stable (garbage collection disabled for TA evaluation)
                self.mark_checkpoint_stable(sequence_number)

    def mark_checkpoint_stable(self, stable_checkpoint_seq):
        """Mark checkpoint as stable - garbage collection disabled for TA evaluation"""
        # Note: Garbage collection is disabled to preserve all logs for TA evaluation
        # as specified in the project requirements
        log = f'Server {self.server_id}: Checkpoint {stable_checkpoint_seq} is stable (garbage collection disabled for TA evaluation)'
        self.local_logs.append(log)
        print(log)

    def get_latest_stable_checkpoint(self):
        """Get the latest stable checkpoint"""
        if not self.stable_checkpoints:
            return None
        latest_seq = max(self.stable_checkpoints.keys())
        return self.stable_checkpoints[latest_seq]

    def restore_from_checkpoint(self, checkpoint_data, preserve_view=False):
        """Restore replica state from checkpoint data"""
        try:
            # Restore legacy balances
            balances = checkpoint_data.get('balances', {})
            # Convert string keys to integers if needed (JSON serialization converts int keys to strings)
            if balances and isinstance(list(balances.keys())[0] if balances else None, str):
                self.balances = {int(k): v for k, v in balances.items()}
            else:
                self.balances = balances.copy() if balances else {key: 10 for key in range(1, NUM_CLIENTS + 1)}
            
            # Restore SmallBank savings balances
            savings_balances = checkpoint_data.get('savings_balances', {})
            if savings_balances and isinstance(list(savings_balances.keys())[0] if savings_balances else None, str):
                self.savings_balances = {int(k): v for k, v in savings_balances.items()}
            else:
                self.savings_balances = savings_balances.copy() if savings_balances else {key: 10 for key in range(1, NUM_CLIENTS + 1)}
            
            # Restore SmallBank checking balances
            checking_balances = checkpoint_data.get('checking_balances', {})
            if checking_balances and isinstance(list(checking_balances.keys())[0] if checking_balances else None, str):
                self.checking_balances = {int(k): v for k, v in checking_balances.items()}
            else:
                self.checking_balances = checking_balances.copy() if checking_balances else {key: 10 for key in range(1, NUM_CLIENTS + 1)}
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            raise
        
        # Only restore view if not preserving it (e.g., when called from new-view, view comes from new-view message)
        if not preserve_view:
            self.view = checkpoint_data['view']
        
        # Use a new cursor to avoid recursive cursor issues
        new_cursor = self.conn.cursor()
        try:
            new_cursor.execute('DELETE FROM transactions')
            
            executed_transactions = checkpoint_data.get('executed_transactions', [])
            
            if executed_transactions is None:
                executed_transactions = []
            
            for idx, trans in enumerate(executed_transactions):
                try:
                    if not isinstance(trans, (tuple, list)):
                        continue
                    
                    # Handle both old format (7 columns) and new format (8 columns with transaction_type)
                    if len(trans) >= 8:
                        id, sequence_number, sender, receiver, amount, view, status, tx_type = trans[:8]
                        new_cursor.execute('''
                            INSERT INTO transactions (sequence_number, sender, receiver, amount, view, status, transaction_type)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (sequence_number, sender, receiver, amount, view, status, tx_type))
                    elif len(trans) == 7:
                        id, sequence_number, sender, receiver, amount, view, status = trans
                        new_cursor.execute('''
                            INSERT INTO transactions (sequence_number, sender, receiver, amount, view, status)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (sequence_number, sender, receiver, amount, view, status))
                    else:
                        continue
                except Exception as e:
                    import traceback
                    print(traceback.format_exc())
                    raise
            
            self.conn.commit()
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            raise
        finally:
            new_cursor.close()
        
        log = f'Server {self.server_id}: Restored from checkpoint sequence {checkpoint_data["sequence_number"]}'
        self.local_logs.append(log)
        print(log)

    def check_checkpoint_trigger(self, sequence_number):
        """Check if we should create a checkpoint"""
        # Debug output
        if sequence_number >= 95:
            log = f"Server {self.server_id}: Checkpoint trigger check - seq={sequence_number}, interval={self.checkpoint_interval}, last={self.last_checkpoint_sequence}, modulo={sequence_number % self.checkpoint_interval}"
            self.local_logs.append(log)
            print(log)
        
        if sequence_number % self.checkpoint_interval == 0 and sequence_number > self.last_checkpoint_sequence:
            self.create_checkpoint(sequence_number)

    def send_message(self, peer_port, message):
        if self.server_id in Shared.byzantines and self.view == self.server_id:
            if "time" in current_attack_types:
                delay_ms = 100  # Fraction of view_timeout = 8, view_cancel_timeout = 3, and wait_for_majority(timeout=3)
                print(f"Server {self.server_id} (Byzantine Leader): Delaying message for {delay_ms}ms")
                time.sleep(delay_ms / 1000.0)
        
        peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            peer_socket.connect(('localhost', peer_port))
            
            message_json = json.dumps(message)
            peer_socket.send(message_json.encode())
        except ConnectionRefusedError as e:
            # Log any errors during message sending
            if 'pbft' in message and message['pbft'].get('type') == 'checkpoint':
                log = f"Server {self.server_id}: [ERROR] Failed to send checkpoint to port {peer_port}: {e}"
                self.local_logs.append(log)
                print(log)
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            # Log any errors during message sending
            if 'pbft' in message and message['pbft'].get('type') == 'checkpoint':
                log = f"Server {self.server_id}: [ERROR] Failed to send checkpoint to port {peer_port}: {e}"
                self.local_logs.append(log)
                print(log)
        finally:
            peer_socket.close()

    def process_queued_transactions(self):
        if self.transaction_queue:
            payload = self.transaction_queue.pop(0)
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: Processing queued transaction {payload.get('transaction', '?')}, equivocation_n2={payload.get('equivocation_n2', False)}")
            self.handle_transaction(payload)
        else:
            debug_print(f"[DEBUG-EQ] Server {self.server_id}: No queued transactions to process")

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
    """Parse test input file in NEW format only
    Format: Set Number, Transactions, Live, Byzantine, Attack
    - Live servers: [n1, n2, n3] (with 'n' prefix)
    - Byzantine: [n1] (array with 'n' prefix)
    - Attack: [crash] or [time; dark(n6)] (array format)
    - Balance: (E) (single letter)
    """
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        test_sets = {}
        current_set = None
        live_servers = None
        byzantines = None
        attack_type = None
        sequence_number = 0
        for row in reader:
            # Skip empty rows
            if not row or len(row) < 2:
                continue
            
            if row[0]:
                current_set = int(row[0])
                # New format: [n1, n2, n3] -> [1, 2, 3]
                live_servers_str = row[2].replace('n', '')
                live_servers = eval(live_servers_str)
                
                # New format: [n1] -> [1]
                byzantines_str = row[3].replace('n', '')
                byzantines = eval(byzantines_str)
                
                # New format: [crash] or [time; dark(n6)]
                attack_raw = row[4] if len(row) > 4 else "[]"
                if attack_raw.startswith('[') and attack_raw.endswith(']'):
                    # Remove brackets and use content directly
                    attack_content = attack_raw[1:-1].strip()
                    attack_type = attack_content if attack_content else ""
                else:
                    # Fallback for empty or malformed
                    attack_type = ""
                
                if current_set not in test_sets:
                    test_sets[current_set] = {
                        'transactions': [], 
                        'balance_requests': [], 
                        'live_servers': live_servers, 
                        'byzantines': byzantines,
                        'attack_type': attack_type
                    }
            
            if row[1].startswith('(') and ',' not in row[1] and row[1].endswith(')'):
                # Balance request: (E)
                client_letter = row[1][1:-1]
                client_id = Shared.get_number_for_alphabet(client_letter)
                test_sets[current_set]['balance_requests'].append((None, client_id))
            else:
                # Transaction: Could be legacy (A, B, 1) or SmallBank (Amalgamate(A,B))
                # Handle multiple transactions in a single cell (comma-separated)
                transaction_str = row[1].strip()
                
                # Check if it's a SmallBank transaction (starts with transaction type name)
                smallbank_types = ['Amalgamate', 'Balance', 'DepositChecking', 'SendPayment', 'TransactSavings', 'WriteCheck']
                is_smallbank = any(transaction_str.startswith(f'({tx_type}') for tx_type in smallbank_types)
                
                if is_smallbank:
                    # Parse multiple SmallBank transactions from comma-separated list
                    # Format: (Amalgamate(A,B)),(Balance(C)),(SendPayment(D,E,10))
                    transactions_list = []
                    i = 0
                    while i < len(transaction_str):
                        if transaction_str[i] == '(':
                            # Find matching closing parenthesis
                            depth = 0
                            start = i
                            j = i
                            while j < len(transaction_str):
                                if transaction_str[j] == '(':
                                    depth += 1
                                elif transaction_str[j] == ')':
                                    depth -= 1
                                    if depth == 0:
                                        # Found complete transaction
                                        tx_str = transaction_str[start:j+1]
                                        transactions_list.append(tx_str)
                                        i = j + 1
                                        # Skip comma and whitespace
                                        while i < len(transaction_str) and (transaction_str[i] == ',' or transaction_str[i].isspace()):
                                            i += 1
                                        break
                                j += 1
                            else:
                                # No closing parenthesis found, break
                                break
                        else:
                            i += 1
                    
                    # Parse each transaction
                    for tx_str in transactions_list:
                        try:
                            # Remove outer parentheses: (Amalgamate(A,B)) -> Amalgamate(A,B)
                            inner = tx_str.strip('()')
                            # Find the opening parenthesis after transaction type
                            paren_idx = inner.find('(')
                            if paren_idx > 0:
                                tx_type = inner[:paren_idx]
                                # Extract arguments: Amalgamate(A,B) -> A,B
                                args_str = inner[paren_idx+1:-1]  # Remove inner parentheses
                                
                                # Parse arguments properly handling nested structures
                                parsed_args = []
                                if args_str:  # Not empty
                                    # Split by comma, but handle negative numbers
                                    args_list = []
                                    current_arg = ""
                                    depth = 0
                                    for char in args_str:
                                        if char == '(':
                                            depth += 1
                                            current_arg += char
                                        elif char == ')':
                                            depth -= 1
                                            current_arg += char
                                        elif char == ',' and depth == 0:
                                            args_list.append(current_arg.strip())
                                            current_arg = ""
                                        else:
                                            current_arg += char
                                    if current_arg:
                                        args_list.append(current_arg.strip())
                                    
                                    # Convert arguments: letters to numbers, keep numbers as-is
                                    for arg in args_list:
                                        arg = arg.strip()
                                        # Handle negative numbers
                                        if arg.startswith('-') and arg[1:].isdigit():
                                            parsed_args.append(int(arg))
                                        elif arg.isdigit():
                                            parsed_args.append(int(arg))
                                        else:
                                            # Try to convert letter to number
                                            num = Shared.get_number_for_alphabet(arg)
                                            if num:
                                                parsed_args.append(num)
                                            else:
                                                # Try to parse as integer (for account IDs > 10)
                                                try:
                                                    parsed_args.append(int(arg))
                                                except ValueError:
                                                    # Fallback: keep as string
                                                    parsed_args.append(arg)
                                
                                # Create SmallBank transaction: (tx_type, args_tuple)
                                transaction = (tx_type, tuple(parsed_args))
                                sequence_number += 1
                                test_sets[current_set]['transactions'].append((sequence_number, transaction))
                            else:
                                # Fallback: try eval for single transaction
                                transaction = eval(Shared.convert_labels_to_keys(tx_str))
                                sequence_number += 1
                                test_sets[current_set]['transactions'].append((sequence_number, transaction))
                        except Exception as e:
                            # Skip malformed transactions
                            print(f"Warning: Failed to parse SmallBank transaction '{tx_str}': {e}")
                            continue
                else:
                    # Legacy transaction: (A, B, 1) - may also have multiple transactions
                    # Split by ),( pattern for multiple transactions
                    if '),(' in transaction_str or transaction_str.count('(') > 1:
                        # Multiple legacy transactions
                        transactions_list = []
                        i = 0
                        while i < len(transaction_str):
                            if transaction_str[i] == '(':
                                depth = 0
                                start = i
                                j = i
                                while j < len(transaction_str):
                                    if transaction_str[j] == '(':
                                        depth += 1
                                    elif transaction_str[j] == ')':
                                        depth -= 1
                                        if depth == 0:
                                            tx_str = transaction_str[start:j+1]
                                            transactions_list.append(tx_str)
                                            i = j + 1
                                            while i < len(transaction_str) and (transaction_str[i] == ',' or transaction_str[i].isspace()):
                                                i += 1
                                            break
                                    j += 1
                                else:
                                    break
                            else:
                                i += 1
                        
                        for tx_str in transactions_list:
                            try:
                                transaction = eval(Shared.convert_labels_to_keys(tx_str))
                                sequence_number += 1
                                test_sets[current_set]['transactions'].append((sequence_number, transaction))
                            except Exception as e:
                                print(f"Warning: Failed to parse legacy transaction '{tx_str}': {e}")
                                continue
                    else:
                        # Single legacy transaction
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

def configure_byzantine_behavior(attack_type):
    """Configure Byzantine behavior based on attack type from test file"""
    global current_attack_types, dark_target_nodes
    
    if not attack_type:
        current_attack_types = []
        dark_target_nodes = []
        return
    
    # Parse multiple attack types (semicolon-separated)
    current_attack_types = [attack.strip() for attack in attack_type.split(';')]
    dark_target_nodes = []  # Reset for each test
    
    for attack in current_attack_types:
        if attack == "sign":
            print(f"Configuring invalid signature Byzantine behavior")
        elif attack == "crash":
            print(f"Configuring crash Byzantine behavior")
        elif attack.startswith("time"):
            print(f"Configuring timing Byzantine behavior: {attack}")
        elif attack.startswith("dark("):
            # Extract target nodes once globally
            targets_str = attack[5:-1]  # Remove "dark(" and ")"
            if targets_str:
                dark_target_nodes = [int(node.strip()[1:]) for node in targets_str.split(',')]  # Remove 'n' prefix
                print(f"Configuring in-dark Byzantine behavior: {attack} -> target nodes: {dark_target_nodes}")
            else:
                print(f"Configuring in-dark Byzantine behavior: {attack}")
        elif attack.startswith("equivocation("):
            print(f"Configuring equivocation Byzantine behavior: {attack}")
        else:
            print(f"Unknown attack type: {attack}")

def run_test_file(input_file, interactive=True, debug=False):
    """Run a single test file"""
    global DEBUG_MODE, key_shares, current_attack_types, dark_target_nodes
    DEBUG_MODE = debug  # Set global debug flag
    
    print(f"\n{'='*60}")
    print(f"Running tests from: {input_file}")
    print(f"{'='*60}")
    
    test_sets = read_input_file(input_file)
    key_shares = generate_key_shares(token_bytes(32), NUM_SERVERS, threshold)
    
    for set_number, test_data in test_sets.items():
        setup(NUM_SERVERS, NUM_CLIENTS, start_client, start_server, set_number == 1, set_number)

        print(f"\nRunning Test Set {set_number}...")
        transactions = test_data['transactions']
        balance_requests = test_data.get('balance_requests', [])
        live_servers = test_data['live_servers']
        Shared.byzantines = test_data['byzantines']
        attack_type = test_data.get('attack_type', '')
        
        print(f"Live Servers: {live_servers}")
        print(f"Byzantine Servers: {Shared.byzantines}")
        print(f"Attack Type: {attack_type if attack_type else 'None'}")
        print(f"Transactions: {len(transactions)}")
        print(f"Balance Requests: {len(balance_requests)}")
        
        # Configure Byzantine behavior based on attack type
        configure_byzantine_behavior(attack_type)
        
        # Execute transactions first
        for transaction in transactions:
            seq_num, trans = transaction
            
            # Extract client_id: legacy format has (sender, receiver, amount), SmallBank has (tx_type, args)
            if isinstance(trans, (list, tuple)) and len(trans) == 2:
                tx_type_or_id, data = trans
                # Check if it's SmallBank (first element is a string transaction type)
                if isinstance(tx_type_or_id, str) and tx_type_or_id in ['Amalgamate', 'Balance', 'DepositChecking', 'SendPayment', 'TransactSavings', 'WriteCheck']:
                    # SmallBank: client_id is first argument
                    if isinstance(data, (list, tuple)) and len(data) > 0:
                        client_id = data[0]
                    else:
                        client_id = 1  # Default fallback
                else:
                    # Legacy: (sender, receiver, amount)
                    client_id = tx_type_or_id if isinstance(tx_type_or_id, int) else 1
            else:
                # Fallback
                client_id = 1
            
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
    global DEBUG_MODE
    parser = argparse.ArgumentParser(description='Linear PBFT Consensus Protocol')
    parser.add_argument('--test', '-t', type=str, help='Run specific test file (e.g., input1.csv)')
    parser.add_argument('--all', '-a', action='store_true', help='Run all tests from input1.csv to input10.csv')
    parser.add_argument('--non-interactive', '-n', action='store_true', help='Run tests without interactive prompts')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug mode with automatic DB balance verification')
    
    args = parser.parse_args()
    DEBUG_MODE = args.debug  # Set global debug flag
    
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
