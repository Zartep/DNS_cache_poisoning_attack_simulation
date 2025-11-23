# -*- coding: UTF-8 -*-
from dnslib import *
from gevent.server import DatagramServer
from time import sleep

# The static IP returned for all queries
DEFAULT_RESPONSE_IP = '1.1.1.1'

class DNSServer(DatagramServer):
    def process_dns_query(self, data, client_address):
        request = DNSRecord.parse(data)
        
        # --- FIX: CASE PRESERVATION ---
        # Retrieve the original DNSLabel object without converting to string and back.
        # This ensures that if "GoOgLe.CoM" arrives, we reply with "GoOgLe.CoM"
        # rather than normalizing it to lowercase.
        preserved_case_qname = request.q.qname
        transaction_id = request.header.id

        dns_response = DNSRecord(
            DNSHeader(qr=1, aa=1, ra=1),
            q=DNSQuestion(preserved_case_qname), # Use the original object
            a=RR(preserved_case_qname, rdata=A(DEFAULT_RESPONSE_IP))
        )
        # -------------------------------------

        dns_response.header.id = transaction_id
        sleep(1.5)
        self.socket.sendto(dns_response.pack(), client_address)

    def handle(self, data, address):
        self.process_dns_query(data, address)

def start_server():
    print("Root Server (0x20 Compatible) running...")
    DNSServer(':53').serve_forever()

if __name__ == '__main__':
    start_server()