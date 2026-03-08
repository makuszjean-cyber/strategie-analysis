import os
import ipaddress
import threading
from datetime import datetime

from .multithread import MultiThread


class BaseScanner(MultiThread):
    def __init__(self, is_cidr_input=False, cidr_ranges=None, output_file=None, **kwargs):
        super().__init__(**kwargs)
        self.is_cidr_input = is_cidr_input
        self.cidr_ranges = cidr_ranges or []
        self.output_file = output_file
        self._metadata_written = False
        self._file_lock = threading.Lock()

    def write_to_file(self, message):
        if self.output_file:
            with self._file_lock:
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    f.write(message + '\n')

    def write_scan_metadata(self, filepath=None):
        if self.output_file and not self._metadata_written:
            with self._file_lock:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    f.write(f"\nScan Time: {timestamp}\n")
                    if filepath:
                        f.write(f"File Scanned: {filepath}\n\n")
                    elif self.cidr_ranges:
                        f.write(f"CIDR Ranges: {', '.join(self.cidr_ranges)}\n\n")
                self._metadata_written = True

    def convert_host_port(self, host, port):
        return host + (f':{port}' if port not in ['80', '443'] else '')

    def get_url(self, host, port):
        port = str(port)
        protocol = 'https' if port == '443' else 'http'
        return f'{protocol}://{self.convert_host_port(host, port)}'

    def _is_cidr(self, text):
        if '/' in text:
            try:
                ipaddress.ip_network(text, strict=False)
                return True
            except ValueError:
                pass
        return False

    def generate_cidr_hosts(self, cidr_ranges):
        for cidr in cidr_ranges:
            try:
                network = ipaddress.ip_network(cidr.strip(), strict=False)
                for ip in network.hosts():
                    yield str(ip)
            except ValueError:
                continue

    def get_total_cidr_hosts(self, cidr_ranges):
        total = 0
        for cidr in cidr_ranges:
            try:
                network = ipaddress.ip_network(cidr.strip(), strict=False)
                total += max(0, network.num_addresses - 2)
            except ValueError:
                continue
        return total

    def set_cidr_total(self, cidr_ranges):
        if self.is_cidr_input and cidr_ranges:
            total_hosts = self.get_total_cidr_hosts(cidr_ranges)
            port_multiplier = len(getattr(self, 'port_list', [1]))
            method_multiplier = len(getattr(self, 'method_list', [1]))
            self.set_total(total_hosts * port_multiplier * method_multiplier)

    def count_hosts_in_file(self, filepath):
        count = 0
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    host = line.strip()
                    if host and not host.startswith(('#', '*')):
                        if self._is_cidr(host):
                            try:
                                network = ipaddress.ip_network(host, strict=False)
                                count += max(0, network.num_addresses - 2)
                            except ValueError:
                                continue
                        else:
                            count += 1
        except (FileNotFoundError, IOError, UnicodeDecodeError):
            pass
        return count

    def set_host_total(self, host_filepath):
        if host_filepath:
            total_hosts = self.count_hosts_in_file(host_filepath)
            port_multiplier = len(getattr(self, 'port_list', [1]))
            method_multiplier = len(getattr(self, 'method_list', [1]))
            self.set_total(total_hosts * port_multiplier * method_multiplier)

    def generate_hosts_from_file(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                for line in file:
                    host = line.strip()
                    if host and not host.startswith(('#', '*')):
                        if self._is_cidr(host):
                            try:
                                network = ipaddress.ip_network(host, strict=False)
                                for ip in network.hosts():
                                    yield str(ip)
                            except ValueError:
                                continue
                        else:
                            yield host
        except (FileNotFoundError, IOError, UnicodeDecodeError):
            return

    def generate_hosts_from_directory(self, directory):
        if not os.path.isdir(directory):
            return
        for filename in sorted(os.listdir(directory)):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath) and not filename.startswith('.'):
                yield from self.generate_hosts_from_file(filepath)

    def count_hosts_in_directory(self, directory):
        total = 0
        if os.path.isdir(directory):
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath) and not filename.startswith('.'):
                    total += self.count_hosts_in_file(filepath)
        return total

    def set_directory_total(self, directory):
        if directory:
            total_hosts = self.count_hosts_in_directory(directory)
            port_multiplier = len(getattr(self, 'port_list', [1]))
            method_multiplier = len(getattr(self, 'method_list', [1]))
            self.set_total(total_hosts * port_multiplier * method_multiplier)
