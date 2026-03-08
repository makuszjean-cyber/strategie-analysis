import os
import ipaddress
from rich import print
from bugscanx.utils.prompts import get_input, get_confirm


def read_cidrs_from_file(filepath):
    valid_cidrs = []
    try:
        with open(filepath, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    ipaddress.ip_network(line, strict=False)
                    valid_cidrs.append(line)
                except ValueError:
                    pass
            
        return valid_cidrs
    except Exception as e:
        print(f"[bold red]Error reading file: {e}[/bold red]")
        return []


def get_cidr_ranges_from_input(cidr_input):
    return [c.strip() for c in cidr_input.split(',')]


def get_common_inputs():
    default_filename = "results.txt"
    output = get_input(
        "Enter output filename",
        default=default_filename
    )
    threads = get_input(
        "Enter threads",
        validators="number",
        default="50"
    )
    return output, threads


def merge_directory_files(directory):
    files = sorted([
        f for f in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, f))
        and not f.startswith('.')
    ])

    if not files:
        print(f"[bold red]No files found in {directory}[/bold red]")
        return None

    print(f"\n[bold cyan]Found {len(files)} file(s) in '{directory}':[/bold cyan]")
    total_entries = 0
    for f in files:
        filepath = os.path.join(directory, f)
        try:
            with open(filepath, 'r', encoding='utf-8') as fh:
                line_count = sum(1 for line in fh if line.strip() and not line.strip().startswith(('#', '*')))
        except (IOError, UnicodeDecodeError):
            line_count = 0
        total_entries += line_count
        print(f"[green]  \u2022 {f} ({line_count} entries)[/green]")

    combined_path = os.path.join(directory, '.combined_scan.tmp')
    with open(combined_path, 'w', encoding='utf-8') as out:
        for f in files:
            filepath = os.path.join(directory, f)
            try:
                with open(filepath, 'r', encoding='utf-8') as inp:
                    for line in inp:
                        line = line.strip()
                        if line and not line.startswith(('#', '*')):
                            out.write(line + '\n')
            except (IOError, UnicodeDecodeError):
                continue

    print(f"[bold green]  \u2192 Merged {total_entries} entries from {len(files)} files[/bold green]\n")
    return combined_path


def get_host_input():
    input_mode = get_input(
        "Select input mode",
        input_type="choice",
        choices=[
            "Single File",
            "Directory (all files)",
            "CIDR Range(s)",
            "CIDR File"
        ]
    )

    if input_mode == "Single File":
        filename = get_input("Enter filename", input_type="file", validators="file")
        return filename, None

    elif input_mode == "Directory (all files)":
        directory = get_input("Enter directory path", default="data", validators="directory")
        combined = merge_directory_files(directory)
        if not combined:
            return None, None
        return combined, None

    elif input_mode == "CIDR Range(s)":
        cidr = get_input("Enter CIDR range(s)", validators="cidr")
        return None, cidr

    elif input_mode == "CIDR File":
        cidr_file = get_input("Enter CIDR file", input_type="file", validators="file")
        cidr = read_cidrs_from_file(cidr_file) if cidr_file else None
        return None, cidr

    return None, None


def get_input_direct(no302=False):
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None, None
        
    port_list = get_input("Enter port(s)", validators="number", default="80").split(',')
    timeout = get_input("Enter timeout", validators="number", default="3", instruction="(seconds)")
    output, threads = get_common_inputs()
    method_list = get_input(
        "Select HTTP method(s)",
        input_type="choice",
        multiselect=True, 
        choices=[
            "GET", "HEAD", "POST", "PUT",
            "DELETE", "OPTIONS", "TRACE", "PATCH"
        ],
        transformer=lambda result: ', '.join(result) if isinstance(result, list) else result
    )
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.direct import CIDRDirectScanner        
        scanner = CIDRDirectScanner(
            method_list=method_list,
            cidr_ranges=cidr_ranges,
            port_list=port_list,
            no302=no302,
            timeout=int(timeout),
            output_file=output
        )
    else:
        from .scanners.direct import HostDirectScanner
        scanner = HostDirectScanner(
            method_list=method_list,
            input_file=filename,
            port_list=port_list,
            no302=no302,
            timeout=int(timeout),
            output_file=output
        )
    
    return scanner, threads


def get_input_proxy():
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None, None
        
    target_url = get_input("Enter target url", default="in1.wstunnel.site", validators="required")
    default_payload = (
        "GET / HTTP/1.1[crlf]"
        "Host: [host][crlf]"
        "Connection: Upgrade[crlf]"
        "Upgrade: websocket[crlf][crlf]"
    )
    payload = get_input("Enter payload", default=default_payload, validators="required")
    port_list = get_input("Enter port(s)", validators="number", default="80").split(',')
    output, threads = get_common_inputs()
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.proxy_check import CIDRProxyScanner
        scanner = CIDRProxyScanner(
            cidr_ranges=cidr_ranges,
            port_list=port_list,
            target=target_url,
            payload=payload,
            output_file=output
        )
    else:
        from .scanners.proxy_check import HostProxyScanner
        scanner = HostProxyScanner(
            input_file=filename,
            port_list=port_list,
            target=target_url,
            payload=payload,
            output_file=output
        )
    
    return scanner, threads


def get_input_proxy2():
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None, None
        
    port_list = get_input("Enter port(s)", validators="number", default="80").split(',')
    output, threads = get_common_inputs()
    method_list = get_input(
        "Select HTTP method(s)",
        input_type="choice",
        multiselect=True, 
        choices=[
            "GET", "HEAD", "POST", "PUT",
            "DELETE", "OPTIONS", "TRACE", "PATCH"
        ],
        transformer=lambda result: ', '.join(result) if isinstance(result, list) else result
    )
    
    proxy = get_input("Enter proxy", instruction="(proxy:port)", validators="required")
    
    use_auth = get_confirm(" Use proxy authentication?")
    proxy_username = None
    proxy_password = None
    
    if use_auth:
        proxy_username = get_input("Enter proxy username", validators="required")
        proxy_password = get_input("Enter proxy password", validators="required")
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.proxy_request import CIDRProxy2Scanner
        scanner = CIDRProxy2Scanner(
            method_list=method_list,
            cidr_ranges=cidr_ranges,
            port_list=port_list,
            output_file=output
        ).set_proxy(proxy, proxy_username, proxy_password)
    else:
        from .scanners.proxy_request import HostProxy2Scanner
        scanner = HostProxy2Scanner(
            method_list=method_list,
            input_file=filename,
            port_list=port_list,
            output_file=output
        ).set_proxy(proxy, proxy_username, proxy_password)

    return scanner, threads


def get_input_ssl():
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None, None
        
    output, threads = get_common_inputs()
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.ssl import CIDRSSLScanner
        scanner = CIDRSSLScanner(
            cidr_ranges=cidr_ranges,
            output_file=output
        )
    else:
        from .scanners.ssl import HostSSLScanner
        scanner = HostSSLScanner(
            input_file=filename,
            output_file=output
        )
    
    return scanner, threads


def get_input_ping():
    filename, cidr = get_host_input()
    if filename is None and cidr is None:
        return None, None, None
        
    port_list = get_input("Enter port(s)", validators="number", default="443").split(',')
    output, threads = get_common_inputs()
    
    if cidr:
        try:
            cidr_ranges = get_cidr_ranges_from_input(cidr)
        except AttributeError:
            cidr_ranges = cidr
        from .scanners.ping import CIDRPingScanner
        scanner = CIDRPingScanner(
            port_list=port_list,
            cidr_ranges=cidr_ranges,
            output_file=output
        )
    else:
        from .scanners.ping import HostPingScanner
        scanner = HostPingScanner(
            input_file=filename,
            port_list=port_list,
            output_file=output
        )
    
    return scanner, threads


def get_user_input():
    mode = get_input(
        "Select scanning mode",
        "choice", 
        choices=[
            "Direct", "DirectNon302", "ProxyTest",
            "ProxyRoute", "Ping", "SSL"
        ]
    )
    
    input_handlers = {
        'Direct': lambda: get_input_direct(no302=False),
        'DirectNon302': lambda: get_input_direct(no302=True),
        'ProxyTest': get_input_proxy,
        'ProxyRoute': get_input_proxy2,
        'Ping': get_input_ping,
        'SSL': get_input_ssl
    }
    
    scanner, threads = input_handlers[mode]()
    return scanner, threads


def main():
    scanner, threads = get_user_input()
    scanner.threads = int(threads)
    scanner.start()
