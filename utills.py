import time
import ipwhois
from scapy.sendrecv import sr1


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
