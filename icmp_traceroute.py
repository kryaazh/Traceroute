from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from Traceroute.utills import is_ipv6, ip_found


def icmp_traceroute(ip, timeout, max_ttl, print_asn):
    conf.verb = 0
    ttl = 1
    while ttl <= max_ttl:
        if is_ipv6(ip):
            icmp_pkt = IPv6(dst=ip, hlim=ttl) / ICMPv6EchoRequest()
        else:
            icmp_pkt = IP(dst=ip, ttl=ttl) / ICMP()

        if ip_found(icmp_pkt, ip, timeout, ttl, print_asn):
            break
        ttl += 1