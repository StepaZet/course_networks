import socket
import dnslib
from cache_controller import DNSCacheController


class DNSServer:
    __IP = '0.0.0.0'

    def __init__(self, port=1488, root_dns_ip='192.203.230.10'):
        self.__port = port
        self.__root_dns_ip = root_dns_ip
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.bind((self.__IP, self.__port))
        self.__cache_controller = DNSCacheController('domains_cache')

    def __get_response(self, data: bytes, ip: str, port=53) -> (bytes, str):
        self.__sock.sendto(data, (ip, port))
        return self.__sock.recvfrom(1024)

    @staticmethod
    def __parse_data(data: bytes) -> dnslib.DNSRecord:
        # Для условно будущих программистов, которые сами распарсят данные
        # Типо архитектура на будущее, если бы тот код был в проекте каком-то
        return dnslib.DNSRecord.parse(data)

    @staticmethod
    def __update_stack_ip_v4(stack_ip: list[str],
                             section: [dnslib.DNSRecord]) -> None:
        for server in section:
            if server.rtype == 1 and server.rdata != []:
                stack_ip.append(str(server.rdata))

    def __create_response_from_cache(
            self, parsed_data: dnslib.DNSRecord) -> bytes:
        domain_name = str(parsed_data.q.qname)
        response = self.__cache_controller.get_data(domain_name)
        parsed_response = self.__parse_data(response)
        parsed_response.header.id = parsed_data.header.id
        parsed_response.header.aa = 0  # Не авторитетный ответ

        new_ttl = int(
            parsed_response.a.ttl
            - self.__cache_controller.get_domain_age(domain_name)
        )

        for i in range(len(parsed_response.rr)):
            parsed_response.rr[i].ttl = new_ttl

        return parsed_response.pack()

    def __try_create_response_from_cache(
            self, parsed_data: dnslib.DNSRecord) -> bytes | None:
        domain_name = str(parsed_data.q.qname)

        if not self.__cache_controller.is_domain_in_cache(domain_name):
            return None

        if not self.__cache_controller.is_domain_valid(domain_name):
            self.__cache_controller.delete_domain(domain_name)
            return None

        return self.__create_response_from_cache(parsed_data)

    @staticmethod
    def __create_multiply_response(
            parsed_data: dnslib.DNSRecord) -> bytes:
        domain_name = str(parsed_data.q.qname)
        multiply_str = '.multiply.'
        start_multiply_str = domain_name.find(multiply_str)
        digits_to_multiply = domain_name[:start_multiply_str].split('.')

        result = 1
        for digit in digits_to_multiply:
            result *= int(digit)
        result %= 256

        response = dnslib.DNSRecord(
            dnslib.DNSHeader(id=parsed_data.header.id, qr=1, aa=0, ra=0),
            q=dnslib.DNSQuestion(domain_name),
            a=dnslib.RR(
                domain_name,
                rdata=dnslib.A(f'127.0.0.{result}')
            )
        )

        return response.pack()

    def __try_create_multiply_response(
            self, parsed_data: dnslib.DNSRecord) -> bytes | None:
        domain_name = str(parsed_data.q.qname)

        if '.multiply.' not in domain_name:
            return None

        return self.__create_multiply_response(parsed_data)

    def __get_dns_response(self, data_client: bytes) -> bytes:
        parsed_data_client = self.__parse_data(data_client)

        # Проверяем кэш
        cache_response = \
            self.__try_create_response_from_cache(parsed_data_client)
        if cache_response:
            return cache_response

        multiply_response = \
            self.__try_create_multiply_response(parsed_data_client)
        if multiply_response:
            return multiply_response

        root_data, _ = self.__get_response(data_client, self.__root_dns_ip)
        parsed_root_data = self.__parse_data(root_data)
        stack_ip = []

        self.__update_stack_ip_v4(stack_ip, parsed_root_data.ar)
        if not stack_ip:  # Корневой сервер ничего не нашел
            return data_client

        while True:
            next_data, _ = self.__get_response(data_client, stack_ip.pop())
            parsed_next_data = self.__parse_data(next_data)

            if parsed_next_data.header.a > 0:
                self.__cache_controller.add_domain(
                    str(parsed_root_data.q.qname),
                    next_data, parsed_next_data.a.ttl)

                return next_data

            tmp_stack = []
            self.__update_stack_ip_v4(tmp_stack, parsed_next_data.ar)

            if len(tmp_stack) > 0:
                stack_ip += tmp_stack
                continue

            authority_section = parsed_next_data.auth
            if len(authority_section) > 0:
                domain_name = str(authority_section[0].rdata)
                new_data = dnslib.DNSRecord.question(domain_name).pack()
                response = self.__get_dns_response(new_data)
                parsed_response = self.__parse_data(response)
                if parsed_response.header.a == 0:
                    return next_data
                self.__update_stack_ip_v4(stack_ip, parsed_response.rr)

    def run(self):
        while True:
            data, addr = self.__sock.recvfrom(1024)
            response = self.__get_dns_response(data)
            self.__sock.sendto(response, addr)
