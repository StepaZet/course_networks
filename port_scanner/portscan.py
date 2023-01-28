from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import click


class PortsRequest:
    def __init__(self, protocol: str, ports: list):
        self.protocol = protocol
        self.ports = ports

    @staticmethod
    def parse_ports_request(ports_request: str) -> 'PortsRequest':
        protocol, ports = ports_request.split('/')
        result_ports = []
        ports = ports.split(',')
        ports = [port.split('-') for port in ports]
        for port in ports:
            if len(port) == 1:
                result_ports.append(int(port[0]))
            else:
                result_ports.extend(range(int(port[0]), int(port[1])))
        return PortsRequest(protocol, result_ports)


class PortScanner:
    def __init__(self, ip: str, ports_requests: list[PortsRequest],
                 timeout=2, verbose=False, guess=False, max_treads=100):
        self.ip = ip
        self.ports_requests = ports_requests
        self.timeout = timeout
        self.verbose = verbose
        self.guess = guess
        self.max_treads = max_treads

        if len(self.ports_requests) == 0:
            self.ports_requests = [
                PortsRequest('tcp', range(1, 1024)),
                PortsRequest('udp', range(1, 1024))
            ]

    def scan(self):
        protocol_to_scan = {
            'tcp': self.scan_tcp,
            'udp': self.scan_udp
        }

        for ports_request in self.ports_requests:
            if ports_request.protocol not in protocol_to_scan:
                raise ValueError(f"Unknown protocol {ports_request.protocol}")

            for port_result in protocol_to_scan[ports_request.protocol](
                    ports_request.ports):
                if port_result[0] is None:
                    continue
                for part in port_result:
                    if part is not None:
                        print(part, end=' ')
                print()

    @staticmethod
    def get_service_name(port: int) -> str:
        try:
            return socket.getservbyport(port)
        except OSError:
            return '-'

    def scan_tcp_port(self, port: int) -> tuple[str, float, str]:
        result, delay, service = None, None, None
        start = time.time()
        response = sr1(IP(dst=self.ip) / TCP(dport=port, flags="S"),
                       timeout=self.timeout, verbose=0)
        end = time.time()
        if response is not None and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                # Закрывает tcp соединение
                send_rst = sr(
                    IP(dst=self.ip) / TCP(dport=port, flags="AR"),
                    timeout=1, verbose=0)
                result = f"TCP {port}"
            if self.verbose:
                delay = round((end - start) * 1000, 2)
            if self.guess:
                service = self.get_service_name(port)

        return result, delay, service

    def scan_udp_port(self, port: int):
        result, delay, service = None, None, None
        start = time.time()
        response = sr1(
            IP(dst=self.ip) / UDP(sport=RandShort(), dport=port)
            / DNS(rd=1, qd=DNSQR(qname=self.ip)),
            timeout=self.timeout, verbose=0)
        end = time.time()
        if response is not None and response.haslayer(UDP):
            result = f"UDP {port}"
            if self.verbose:
                delay = round((end - start) * 1000, 2)
            if self.guess:
                service = self.get_service_name(port)

        return result, delay, service

    def scan_tcp(self, ports: list):
        tasks = []
        with ThreadPoolExecutor(max_workers=self.max_treads) as executor:
            for port in ports:
                tasks.append(executor.submit(self.scan_tcp_port, port))
            for task in as_completed(tasks):
                yield task.result()

    def scan_udp(self, ports: list):
        tasks = []
        with ThreadPoolExecutor(max_workers=self.max_treads) as executor:
            for port in ports:
                tasks.append(executor.submit(self.scan_udp_port, port))
            for task in as_completed(tasks):
                yield task.result()


@click.command()
@click.option('--verbose', '-v', is_flag=True, help='Verbose mode')
@click.option('--guess', '-g', is_flag=True, help='Guess service name')
@click.option('--timeout', '-t', default=2, help='Timeout')
@click.option('--num-threads', '-j', default=100, help='Number of threads')
@click.argument('ip', nargs=1)
@click.argument('ports_requests', nargs=-1)
def main(verbose, guess, timeout, num_threads, ip, ports_requests):
    conf.L3socket = L3RawSocket
    ports_requests = [PortsRequest.parse_ports_request(ports_request)
                      for ports_request in ports_requests]
    scanner = PortScanner(ip, ports_requests, timeout, verbose, guess,
                          num_threads)
    scanner.scan()


if __name__ == '__main__':
    main()
