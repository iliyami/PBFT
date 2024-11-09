import hashlib
import threading
import socket
import json
import time
from shared import Shared

class PBFTClient():
    def __init__(self, client_id, client_port):
        super().__init__()
        self.client_id = client_id
        self.signature = generate_signature(client_id)
        self.client_host = 'localhost'
        self.port = client_port
        self.primary_server_host = 'localhost'
        self.retry_timeout = 5
        self.replies_received = 0
        self.response_lock = threading.Lock()
        self.condition = threading.Condition(self.response_lock)

    def start_client(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_socket.bind(('localhost', self.port))
        client_socket.listen(5)
        print(f"Client {self.client_id} started on port {self.port}")
        
        # Start a thread for accepting server connections for receiving replies
        threading.Thread(target=self.accept_connections, args=(client_socket,)).start()

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

    def handle_reply(self, request):
        with self.response_lock:
            if request['reply'] == 'no':
                return
            self.replies_received += 1
            if self.replies_received >= 3:
                self.condition.notify()


    def send_request(self, request):
        try:
            if 'client' not in request:
                request['client'] = {
                    'id': self.client_id,
                    'signature': self.signature,
                    'timestamp': time.time()
                }
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            leader_port = 5000 + Shared.leader_id
            sock.connect((self.primary_server_host, leader_port))
            sock.sendall(json.dumps(request).encode())
            self.response_lock = threading.Lock()
            self.condition = threading.Condition(self.response_lock)
            self.wait_for_replies(request=request)
        except ConnectionRefusedError:
            print(f"Error: Could not connect to client on port {leader_port}. Is the client running?")
        except Exception as e:
            print(f"Unexpected error: {e}")
        finally:
            sock.close()

    def wait_for_replies(self, request, timeout=5):
        """Wait for f+1 responses or timeout"""
        with self.condition:
            self.condition.wait_for(lambda: self.replies_received >= 3, timeout=timeout)
            if self.replies_received >= 3:
                print(f"Client {self.client_id}: f+1 of replies received.")
                self.replies_received = 0
            else:
                print(f"Client {self.client_id}: Timeout reached, Resending the request!")
                self.replies_received = 0
                self.send_request(request)

def generate_signature(server_id):
    value = str(server_id)
    hash_object = hashlib.sha256(value.encode())
    hash_hex = hash_object.hexdigest()
    return hash_hex
