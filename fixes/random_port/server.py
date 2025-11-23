import dnslib
from gevent.server import DatagramServer
from gevent import socket
from random import randint

UPSTREAM_DNS_IP = '192.168.100.5'
LOCAL_INTERFACE_IP = '192.168.100.2'

# ... (InMemoryStore class identical to original) ...
class InMemoryStore:
    def __init__(self):
        self._db = {}
    def fetch(self, domain_key):
        return self._db.get(domain_key)
    def store(self, domain_key, raw_packet):
        self._db[domain_key] = raw_packet

record_store = InMemoryStore()

class DNSProxy(DatagramServer):
    def handle(self, packet_data, client_addr):
        incoming_packet = dnslib.DNSRecord.parse(packet_data)
        requested_fqdn = str(incoming_packet.q.qname)
        client_tx_id = incoming_packet.header.id

        cached_response_data = record_store.fetch(requested_fqdn)

        if cached_response_data:
            # Cache hit: serve directly
            response_packet = dnslib.DNSRecord.parse(cached_response_data)
            response_packet.header.id = client_tx_id
            self.socket.sendto(response_packet.pack(), client_addr)
        else:
            # Cache miss: forward to upstream
            upstream_query = dnslib.DNSRecord.parse(packet_data)
            
            # Weak Transaction ID (left as original to isolate this specific fix)
            proxy_tx_id = randint(0, 50)
            upstream_query.header.id = proxy_tx_id

            upstream_endpoint = (UPSTREAM_DNS_IP, 53)
            
            upstream_socket = socket.socket(type=socket.SOCK_DGRAM)
            
            # --- FIX: PORT RANDOMIZATION ---
            # Instead of fixed port 7777, we use 0. The kernel will assign a random high ephemeral port.
            # This forces the attacker to guess among ~60,000 ports instead of just 1.
            upstream_socket.bind((LOCAL_INTERFACE_IP, 0)) 
            # ----------------------------------
            
            upstream_socket.connect(upstream_endpoint)
            upstream_socket.send(upstream_query.pack())

            while True:
                # Increased buffer for safety
                try:
                    # Timeout is essential to prevent blocking if the port is random and packet is lost
                    upstream_socket.settimeout(2.0) 
                    raw_upstream_response, _ = upstream_socket.recvfrom(65535)
                except socket.timeout:
                    break

                decoded_upstream_response = dnslib.DNSRecord.parse(raw_upstream_response)
                
                # Basic ID check
                if decoded_upstream_response.header.id == proxy_tx_id:
                    resolved_fqdn = str(decoded_upstream_response.q.qname)
                    record_store.store(resolved_fqdn, raw_upstream_response)
                    
                    # Adapt ID and send back to client
                    decoded_upstream_response.header.id = client_tx_id
                    self.socket.sendto(decoded_upstream_response.pack(), client_addr)
                    break
            
            upstream_socket.close()

def start_service():
    print("DNS Service (Port Randomization Fix) started...")
    DNSProxy('192.168.100.2:53').serve_forever()

if __name__ == '__main__':
    start_service()