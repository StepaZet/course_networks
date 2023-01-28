import sys
from enum import Enum
import socket
import time

import click
import ipwhois

from scapy import packet
from scapy.config import conf
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.all import sr1
from scapy.supersocket import L3RawSocket


def timer(func: callable):
    def wrapper(*args, **kwargs) -> tuple:
        start = time.time()
        result = func(*args, **kwargs)
        finish = time.time()
        return result, finish - start
    return wrapper


class ProtocolEnum(Enum):
    TCP = 0
    UDP = 1
    ICMP = 2

    @staticmethod
    def parse(protocol: str) -> 'ProtocolEnum':
        protocol = protocol.lower()
        if protocol == 'tcp':
            return ProtocolEnum.TCP
        elif protocol == 'udp':
            return ProtocolEnum.UDP
        elif protocol == 'icmp':
            return ProtocolEnum.ICMP
        else:
            raise ValueError(f"Unknown protocol {protocol}")


class Tracerouter:
    def __init__(self, destination: str, str_protocol: str,
                 port: int = -1, timeout: int = 2,
                 max_ttl: int = 25, verbose: bool = False):
        self.__destination = destination
        self.__protocol = ProtocolEnum.parse(str_protocol)
        self.__timeout = timeout
        self.__max_ttl = max_ttl
        self.__verbose = verbose
        self.__max_attempt = 3
        self.__port = port
        if self.__port == -1:
            if self.__protocol == ProtocolEnum.TCP:
                self.__port = 80
            elif self.__protocol == ProtocolEnum.UDP:
                self.__port = 53

        conf.L3socket = L3RawSocket

    def __get_packet(self, ttl: int) -> packet:
        if self.__is_ipv6(self.__destination):
            ip = IPv6(dst=self.__destination, hlim=ttl)
        else:
            ip = IP(dst=self.__destination, ttl=ttl)
        if self.__protocol == ProtocolEnum.TCP:
            return ip / TCP(dport=self.__port)
        if self.__protocol == ProtocolEnum.UDP:
            return ip / UDP(dport=self.__port)
        if self.__protocol == ProtocolEnum.ICMP:
            if self.__is_ipv6(self.__destination):
                return ip / ICMPv6EchoRequest()
            else:
                return ip / ICMP()

        raise ValueError(f"Unknown protocol {self.__protocol}")

    @timer
    def __exchange_packets(self, request: packet) -> packet:
        return sr1(request, timeout=self.__timeout, verbose=False)

    def run(self):
        number = 1
        for ttl in range(1, self.__max_ttl + 1):
            _packet = self.__get_packet(ttl)
            response, delay = None, 0
            for attempt in range(self.__max_attempt):
                response, delay = self.__exchange_packets(_packet)
                if response is not None:
                    break
            if not response:
                print(f'{number}\t*')
            else:
                interval = round(delay * 1000, 2)
                output = f'{number}\t{response.src:<15}\t{interval:<5} ms'
                if self.__verbose:
                    ip_domain = self.__get_as(response.src)
                    output += f'\t{ip_domain}'
                print(output)
                if self.__destination == response.src:
                    break
            number += 1

    @staticmethod
    def __get_as(ip: str) -> str:
        try:
            res = ipwhois.IPWhois(ip).lookup_rdap(depth=1)['asn']
            if res is None:
                res = 'NA'
            return res.split(' ')[0]
        except ipwhois.exceptions.IPDefinedError:
            return 'NA'

    @staticmethod
    def __is_ipv6(ip: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False


@click.command()
@click.option('--timeout', '-t', default=2, help='Timeout')
@click.option('--port', '-p', default=-1, help='Port')
@click.option('--max_ttl', '-n', default=25, help='Max TTL')
@click.option('--verbose', '-v', is_flag=True,
              default=False, help='Verbose mode')
@click.argument('ip', nargs=1)
@click.argument('protocol', nargs=-1)
def main(timeout: int, port: int,
         max_ttl: int, verbose: bool,
         ip: str, protocol: str):

    tracerouter = Tracerouter(ip, protocol[0], port,
                              timeout, max_ttl, verbose)
    tracerouter.run()


if __name__ == '__main__':
    main(sys.argv[1:])
