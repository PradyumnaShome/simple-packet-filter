import csv
from intervaltree import Interval, IntervalTree


class Firewall:
    @staticmethod
    def get_decimal_from_octet(octet_string):
        """
        Converts the 4 octets in an IPv4 address to a decimal value.
        """
        decimal = 0
        numbers = octet_string.split(".")
        numbers.reverse()
        for i, number in enumerate(numbers):
            decimal += int(number) * 256**i

        return decimal

    def __init__(self, path):
        """
        Accepts a path to a CSV file containing Firewall rules.
        Internally represents these rules using an interval tree to efficiently make range searches. 
        """
        with open(path) as file:
            csv_reader = csv.reader(file, delimiter=',')
            self.data = [row for row in csv_reader]

        self.tree = IntervalTree()
        for row in self.data:
            direction = row[0]
            protocol = row[1]
            port = row[2]

            port_range = None
            if '-' in port:
                split_port = port.split('-')
                port_range = (int(split_port[0]), int(split_port[1]))
            else:
                # Since port_range is inclusive
                port_range = (int(port), int(port))

            ip_address = row[3]

            if '-' in ip_address:
                split_ip = ip_address.split('-')
                beginning_ip = split_ip[0]
                end_ip = split_ip[1]
                ip_range = (Firewall.get_decimal_from_octet(beginning_ip),
                            Firewall.get_decimal_from_octet(end_ip) + 1
                            )  # Library uses exclusive bounds
            else:
                # Since IP address range is inclusive
                ip_decimal = Firewall.get_decimal_from_octet(ip_address)
                ip_range = (ip_decimal, ip_decimal + 1)

            self.tree[ip_range[0]:ip_range[1]] = {
                "direction": direction,
                "protocol": protocol,
                "port_range": port_range
            }

    def accept_packet(self, direction, protocol, port, ip_address):
        """
        Accepts a packet, defined by direction, protocol, port, and ip address, and returns a boolean representing whether the packet is allowed through the firewall.
        """
        decimal_ip_address = Firewall.get_decimal_from_octet(ip_address)
        rules = self.tree[decimal_ip_address]
        for element in rules:
            rule = element.data
            if int(port) < rule['port_range'][0] or int(
                    port) > rule['port_range'][1]:
                continue

            if rule['protocol'] != protocol:
                continue

            if rule['direction'] != direction:
                continue

            return True

        return False
