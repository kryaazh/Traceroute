from scapy.config import conf
from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import IPv6
from Traceroute.utills import is_ipv6, ip_found


def udp_traceroute(ip, port, timeout, max_ttl, print_asn):
    conf.verb = 0
    ttl = 1
    while ttl <= max_ttl:
        if is_ipv6(ip):
            udp_pkt = IPv6(dst=ip, hlim=ttl) / UDP(dport=port)
        else:
            udp_pkt = IP(dst=ip, ttl=ttl) / UDP(dport=port)

        if ip_found(udp_pkt, ip, timeout, ttl, print_asn):
            break
        ttl += 1