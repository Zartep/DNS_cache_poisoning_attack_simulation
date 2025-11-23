import dnslib
import gevent
from gevent.server import DatagramServer
from gevent import socket
from random import randint

# Remote IP configuration
REMOTE_DNS = '192.168.100.5'
LOCAL_BIND_IP = '192.168.100.2'

class InMemoryStore:
    """Temporary record storage management."""
    def __init__(self):
        self._db = {}

    def fetch(self, domain_key):
        return self._db.get(domain_key)

    def store(self, domain_key, raw_packet):
        self._db[domain_key] = raw_packet

# Global store instance
record_store = InMemoryStore()

class DNSProxy(DatagramServer):

    def handle(self, packet_data, client_addr):
        # Incoming packet parsing
        in_pkg = dnslib.DNSRecord.parse(packet_data)
        query_domain = str(in_pkg.q.qname)
        original_tx_id = in_pkg.header.id

        # Check presence in memory
        cached_blob = record_store.fetch(query_domain)

        if cached_blob:
            # Found in memory, direct send
            out_pkg = dnslib.DNSRecord.parse(cached_blob)
            out_pkg.header.id = original_tx_id
            self.socket.sendto(out_pkg.pack(), client_addr)

        else:
            # Not found, forwarding request
            proxy_req = dnslib.DNSRecord.parse(packet_data)
            
            # Generating new transaction ID for upstream
            new_tx_id = randint(0, 50)
            proxy_req.header.id = new_tx_id

            upstream_endpoint = (REMOTE_DNS, 53)
            
            # UDP socket setup for external communication
            udp_sock = socket.socket(type=socket.SOCK_DGRAM)
            udp_sock.bind((LOCAL_BIND_IP, 7777))
            udp_sock.connect(upstream_endpoint)
            
            # Send to remote server
            udp_sock.send(proxy_req.pack())

            # Loop waiting for correct response
            while True:
                raw_resp, _ = udp_sock.recvfrom(8192)
                parsed_resp = dnslib.DNSRecord.parse(raw_resp)

                if parsed_resp.header.id == new_tx_id:
                    # Correct response received
                    found_domain = str(parsed_resp.q.qname)
                    
                    # Saving
                    record_store.store(found_domain, raw_resp)
                    
                    # ID adaptation and send to original client
                    parsed_resp.header.id = original_tx_id
                    print(parsed_resp)
                    
                    # Note: here I use client_addr received at the beginning
                    self.socket.sendto(parsed_resp.pack(), client_addr)
                    break

def start_service():
    print("DNS Service started...")
    server_instance = DNSProxy('192.168.100.2:53')
    server_instance.serve_forever()

if __name__ == '__main__':
    start_service()