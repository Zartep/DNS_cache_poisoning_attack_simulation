# -*- coding: UTF-8 -*-

from dnslib import *
import gevent
from gevent.server import DatagramServer
from gevent import socket
from random import randint
from time import sleep

# Fixed IP for all DNS responses
fixed_response_ip = '1.1.1.1'

class DNSServer(DatagramServer):
    """
    DNS Server that always responds with the same fixed IP
    """

    def process_dns_query(self, data, client_address):
        """
        Processes a DNS query and responds with a default IP
        """
        # Parse DNS request
        request = DNSRecord.parse(data)
        query_domain = str(request.q.qname)
        transaction_id = request.header.id

        # DNS response construction
        dns_response = DNSRecord(
            DNSHeader(qr=1, aa=1, ra=1),  # qr=1: response, aa=1: authoritative, ra=1: recursion available
            q=DNSQuestion(query_domain),   # Query section
            a=RR(query_domain, rdata=A(fixed_response_ip))  # Answer section with fixed IP
        )

        # Sets transaction ID and adds delay
        dns_response.header.id = transaction_id
        sleep(1.5)  # Artificial delay
        
        # Sending response to the client
        self.socket.sendto(dns_response.pack(), client_address)

    def handle(self, data, address):
        """
        Main handler for incoming UDP packets
        """
        self.process_dns_query(data, address)


def start_server():
    """
    Starts the DNS server on port 53
    """
    DNSServer(':53').serve_forever()


if __name__ == '__main__':
    start_server()