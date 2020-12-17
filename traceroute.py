import argparse
from Traceroute.icmp_traceroute import icmp_traceroute
from Traceroute.tcp_traceroute import tcp_traceroute
from Traceroute.udp_traceroute import udp_traceroute


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


if __name__ == "__main__":
    traceroute()
