import argparse
import ipwhois
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest


def parse():
    parser = argparse.ArgumentParser(description="Traceroute")
    parser.add_argument(
        '-t', '--timeout',
        dest="timeout",
        help="Timeout waiting for a response",
        type=int, default=2
    )
    parser.add_argument(
        '-p', '--port',
        dest="port",
        help="Port (for tcp or udp)",
        type=int
    )
    parser.add_argument(
        '-n', '--hops',
        dest="max_ttl",
        help="Maximum count of requests",
        type=int, default=30
    )
    parser.add_argument(
        '-v', '--verbose',
        dest="print_asn",
        help="Print autonomous system number",
        action="store_true"
    )
    parser.add_argument(
        'ip',
        help="IP Address (IPv4 or IPv6)"
    )
    parser.add_argument(
        'protocol',
        help="TCP/UDP/ICMP",
        choices=['tcp', 'udp', 'icmp']
    )

    return parser.parse_args()


def is_ipv6(ip):
    if ':' in ip:
        return True
    else:
        return False


def get_asn(ip):
    try:
        return ipwhois.IPWhois(ip).lookup_rdap()['asn']
    except ipwhois.IPDefinedError:
        return '-'


def traceroute():
    args = parse()

    if args.protocol == "tcp":
        tcp_traceroute(args.ip, args.port, args.timeout, args.max_ttl,
                       args.print_asn)

    elif args.protocol == "udp":
        udp_traceroute(args.ip, args.port, args.timeout, args.max_ttl,
                       args.print_asn)

    elif args.protocol == "icmp":
        icmp_traceroute(args.ip, args.timeout, args.max_ttl, args.print_asn)


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


def ip_found(pkt, ip, timeout, ttl, print_asn):
    start = time.time()
    response = sr1(pkt, timeout=timeout)
    finish = time.time()
    an_time = round((finish - start) * 1000)

    if not response:
        print(f'{ttl} *')
    else:
        if print_asn:
            print(f'{ttl} {response.src} {an_time} ms {get_asn(response.src)}')
        else:
            print(f'{ttl} {response.src} {an_time} ms')
        if ip == response.src:
            return True


if __name__ == "__main__":
    traceroute()
