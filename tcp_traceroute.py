from scapy.config import conf
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6
from Traceroute.utills import is_ipv6, ip_found


def tcp_traceroute(ip, port, timeout, max_ttl, print_asn):
    conf.verb = 0
    ttl = 1
    while ttl <= max_ttl:
        if is_ipv6(ip):
            tcp_pkt = IPv6(dst=ip, hlim=ttl) / TCP(dport=port)
        else:
            tcp_pkt = IP(dst=ip, ttl=ttl) / TCP(dport=port)

        if ip_found(tcp_pkt, ip, timeout, ttl, print_asn):
            break
        ttl += 1