import hashlib
from queue import Queue
import threading
import socket
import json
import time
from shared import Shared

class PBFTClient():
    def __init__(self, client_id, client_port, server_counts):
        super().__init__()
        self.client_id = client_id
        self.server_counts = server_counts
        self.signature = generate_signature(client_id)
        self.client_host = 'localhost'
        self.port = client_port
        self.primary_server_host = 'localhost'
        self.attempts = 0
        self.timeout = 10
        self.replies_received = 0
        self.view = 1
        self.pending_req = False
        self.queue = Queue()
        self.response_lock = threading.Lock()
        self.condition = threading.Condition(self.response_lock)
        
        # Read-only request tracking
        self.balance_replies = {}  # query_id -> list of replies
        self.balance_replies_lock = threading.Lock()
        self.balance_condition = threading.Condition(self.balance_replies_lock)
        self.balance_conditions = {}  # query_id -> condition variable
        
        # Balance request queue
        self.balance_request_queue = Queue()
        self.balance_processing = False
        
    def process_balance_requests(self):
        """Process balance requests from the queue"""
        while True:
            try:
                client_to_query = self.balance_request_queue.get()
                if client_to_query is None:  # Shutdown signal
                    break
                self.send_balance_request(client_to_query)
                self.balance_request_queue.task_done()
                # Add delay between balance requests to prevent conflicts
                time.sleep(1)
            except Exception as e:
                print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Error processing balance request: {e}")

    def start_client(self, init):
        if init:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.bind(('localhost', self.port))
            client_socket.listen(5)
            # Start a thread for accepting server connections for receiving replies
            threading.Thread(target=self.accept_connections, args=(client_socket,)).start()
        print(f"Client {self.client_id} started on port {self.port}")

    def accept_connections(self, server_socket):
        while True:
            client_conn, _ = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_conn,)).start()

    def handle_client(self, conn):
        data = conn.recv(1024).decode()
        request = json.loads(data)
        if 'transaction' in request:
            self.send_request(request)
        elif 'reply' in request:
            self.handle_reply(request)
        elif 'balance_reply' in request:
            self.handle_balance_reply(request)
        elif 'request_type' in request and request['request_type'] == Shared.REQUEST_TYPE_BALANCE:
            self.handle_balance_request(request)

    def handle_balance_request(self, request):
        client_id = request['balance_query']['client_id']
        query_id = request['balance_query']['query_id']
        client_name = Shared.get_alphabet_for_number(client_id)
        print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Starting balance request for {client_name} (query_id: {query_id})")
        
        # Initialize replies for this query FIRST
        with self.balance_replies_lock:
            self.balance_replies[query_id] = []
        
        # Create condition and lock for this specific request (like regular requests)
        balance_response_lock = threading.Lock()
        balance_condition = threading.Condition(balance_response_lock)
        
        # Store the condition for this query
        self.balance_conditions[query_id] = balance_condition
        
        # Broadcast the request
        self.broadcast(request)
        print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Sent balance request for {client_name} to all servers")
        
        # Wait for 2f+1 replies (following the same pattern as regular requests)
        self.wait_for_balance_replies(query_id, client_id, client_name)

    def wait_for_balance_replies(self, query_id, client_id, client_name):
        """Wait for 2f+1 balance replies (following the same pattern as regular requests)"""
        balance_condition = self.balance_conditions[query_id]
        
        with balance_condition:
            success = balance_condition.wait_for(
                lambda: query_id in self.balance_replies and len(self.balance_replies[query_id]) >= 5,
                timeout=self.timeout
            )
            
            if success:
                # Check if all replies have the same balance
                balances = [reply['balance_reply']['balance'] for reply in self.balance_replies[query_id]]
                if len(set(balances)) == 1:  # All balances are the same
                    balance = balances[0]
                    print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Balance query successful - {client_name} has balance {balance}")
                    # Clean up
                    del self.balance_replies[query_id]
                    del self.balance_conditions[query_id]
                    return balance
                else:
                    print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Balance query failed - inconsistent replies")
                    # Clean up
                    if query_id in self.balance_replies:
                        del self.balance_replies[query_id]
                    if query_id in self.balance_conditions:
                        del self.balance_conditions[query_id]
                    return None
            else:
                print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Balance query timeout - retrying as read-write request")
                # Clean up
                if query_id in self.balance_replies:
                    del self.balance_replies[query_id]
                if query_id in self.balance_conditions:
                    del self.balance_conditions[query_id]
                return None

    def handle_reply(self, request):
        try:
            with self.response_lock:
                self.replies_received += 1
                if self.replies_received >= 3:
                    self.view = request['v']
                    self.condition.notify()
        except Exception as e:
            return

    def handle_balance_reply(self, request):
        """Handle balance replies from servers"""
        try:
            balance_reply = request['balance_reply']
            client_id = balance_reply['client_id']
            balance = balance_reply['balance']
            server_id = balance_reply['server_id']
            query_id = balance_reply['query_id']
            client_name = Shared.get_alphabet_for_number(client_id)
            
            with self.balance_replies_lock:
                if query_id not in self.balance_replies:
                    self.balance_replies[query_id] = []
                self.balance_replies[query_id].append(request)
                print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Received balance reply for {client_name} = {balance} from Server {server_id} (query_id: {query_id}, total replies: {len(self.balance_replies[query_id])})")
                # Notify waiting threads when we have enough replies
                if len(self.balance_replies[query_id]) >= 5 and query_id in self.balance_conditions:
                    print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Notifying condition for query_id {query_id}")
                    # Need to acquire the condition's lock before notifying
                    balance_condition = self.balance_conditions[query_id]
                    with balance_condition:
                        balance_condition.notify()
        except Exception as e:
            print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Error handling balance reply: {e}")
            return


    def send_request(self, request):
        try:
            if self.pending_req:
                self.queue.put(request)
                return
            self.pending_req = True
            if 'client' not in request:
                request['client'] = {
                    'id': self.client_id,
                    'signature': self.signature,
                    'timestamp': time.time()
                }
            self.attempts += 1
            leader_port = 5000 + self.view
            if self.attempts >= 2:
                # print(f'client broadcasting req: {request}')
                self.broadcast(request)
            else:
                # print(f'client: {self.client_id} single request req: {request}')
                self.single_send(request, leader_port)
            self.response_lock = threading.Lock()
            self.condition = threading.Condition(self.response_lock)
            self.wait_for_replies(request=request, timeout=self.timeout+(2 * self.attempts))
        except ConnectionRefusedError:
            print(f"Error: Could not connect to client on port {leader_port}. Is the client running?")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def single_send(self, request, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('localhost', port))
            sock.send(json.dumps(request).encode())
        finally:
            sock.close()

    def broadcast(self, request):
        for replica_port in range(5001, 5001+self.server_counts):
            self.single_send(request, replica_port)

    def wait_for_replies(self, request, timeout):
        """Wait for f+1 responses or timeout"""
        with self.condition:
            self.condition.wait_for(lambda: self.replies_received >= 3, timeout=timeout)
            if self.replies_received >= 3:
                self.replies_received = 0
                self.attempts = 0
                self.pending_req = False
                print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: f+1 of replies received within view {self.view} n={request['transaction'][0]}")
                if self.queue.empty() == False:
                    self.send_request(self.queue.get())
            else:
                print(f"Client {Shared.get_alphabet_for_number(self.client_id)}: Timeout reached, Resending the request n={request['transaction'][0]}!")
                self.replies_received = 0
                self.pending_req = False
                self.send_request(request)


def generate_signature(server_id):
    value = str(server_id)
    hash_object = hashlib.sha256(value.encode())
    hash_hex = hash_object.hexdigest()
    return hash_hex
