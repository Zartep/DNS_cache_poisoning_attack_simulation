import dnslib
from gevent.server import DatagramServer
from gevent import socket
from random import randint, choice

UPSTREAM_DNS_IP = '192.168.100.5'
LOCAL_INTERFACE_IP = '192.168.100.2'
dns_cache = {}

def apply_0x20_encoding(domain_str):
    """
    Randomly transforms 'google.com' into mixed-case 'GoOgLe.CoM'.
    This adds entropy to the request to prevent spoofing.
    """
    if domain_str.endswith('.'): domain_str = domain_str[:-1]
    result = []
    for char in domain_str:
        if char.isalpha():
            if randint(0, 1):
                result.append(char.upper())
            else:
                result.append(char.lower())
        else:
            result.append(char)
    return "".join(result) + "."

class DNSProxy(DatagramServer):
    def handle(self, packet_data, client_addr):
        incoming_packet = dnslib.DNSRecord.parse(packet_data)
        
        # Normalize to lowercase for the local cache lookup key
        # (The cache doesn't care about casing, only the verification does)
        normalized_cache_key = str(incoming_packet.q.qname).lower()
        original_tx_id = incoming_packet.header.id

        if normalized_cache_key in dns_cache:
            # Cache Hit: Return stored response
            cached_packet = dnslib.DNSRecord.parse(dns_cache[normalized_cache_key])
            cached_packet.header.id = original_tx_id
            self.socket.sendto(cached_packet.pack(), client_addr)
        else:
            # Cache Miss: Forward request upstream
            upstream_query = dnslib.DNSRecord.parse(packet_data)
            
            # Using a predictable ID (0-50) to demonstrate that 0x20 protects 
            # even when TXIDs are weak.
            new_tx_id = randint(0, 50) 
            upstream_query.header.id = new_tx_id

            # --- FIX: 0x20 ENCODING (Sending) ---
            original_qname_str = str(upstream_query.q.qname)
            randomized_qname = apply_0x20_encoding(original_qname_str)
            
            # Overwrite the question with the Mixed Case version
            upstream_query.q.qname = dnslib.DNSLabel(randomized_qname)
            # ----------------------------------

            upstream_endpoint = (UPSTREAM_DNS_IP, 53)
            upstream_socket = socket.socket(type=socket.SOCK_DGRAM)
            upstream_socket.bind((LOCAL_INTERFACE_IP, 7777)) # Fixed source port
            upstream_socket.connect(upstream_endpoint)
            upstream_socket.send(upstream_query.pack())

            while True:
                try:
                    upstream_socket.settimeout(2.0)
                    raw_resp, _ = upstream_socket.recvfrom(8192)
                    parsed_resp = dnslib.DNSRecord.parse(raw_resp)

                    if parsed_resp.header.id == new_tx_id:
                        # --- FIX: 0x20 ENCODING (Verification) ---
                        response_qname = str(parsed_resp.q.qname)
                        
                        # If the response does not match the Mixed Case EXACTLY, it's a fake.
                        # (e.g. We sent 'ExAmPlE.com', attacker sent 'example.com')
                        if response_qname != randomized_qname:
                            print(f"ATTACK DETECTED OR LEGACY SERVER! Expected: {randomized_qname}, Received: {response_qname}")
                            continue # Drop packet and keep waiting
                        # -------------------------------------

                        dns_cache[normalized_cache_key] = raw_resp
                        parsed_resp.header.id = original_tx_id
                        self.socket.sendto(parsed_resp.pack(), client_addr)
                        break
                except Exception as e:
                    break
            upstream_socket.close()

def start_service():
    print("DNS Service (0x20 Security Fix) started...")
    DNSProxy('192.168.100.2:53').serve_forever()

if __name__ == '__main__':
    start_service()