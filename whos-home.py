import argparse
import concurrent.futures
import os
import sys
import threading
import time
from typing import List, Dict, Any, Set

import nmap


def parse_args() -> argparse.Namespace:
    """
    Get the CLI arguments.
    :return: The arguments parsed from the CLI as a Namespace object.
    """
    parser = argparse.ArgumentParser(description='LAN scanner')
    parser.add_argument('-i', '--ip-range', dest='ip_range', help='IP range(s) to scan', required=True)

    parser.add_argument('--port-scan', dest='port_scan', choices=['default', 'all-ports'],
                        help='Perform Nmap scan: "default" (top 1000 ports) or "all-ports"')

    parser.add_argument('-A', '--aggressive-port-scan', dest='aggressive_port_scan',
                        help='Enable aggressive Nmap scan mode', action='store_true')

    parser.add_argument('--ping-method', dest='ping_method', choices=['icmp', 'arp', 'full'],
                        default='full', help='Specify the ping methods to use (default: full)')

    parser.add_argument('--max-workers', dest='max_workers', type=int, default=14,
                        help='Maximum number of concurrent nmap scan workers (default: 30)')

    parser.add_argument('--progress-timeout', dest='progress_timeout', type=int, default=60,
                        help='Time in seconds before showing in-progress scans (default: 30)')
    return parser.parse_args()


def discover_hosts(ip_range: str, ping_method: str = 'full') -> List[Dict[str, str]]:
    """
    Discovers hosts on a given IP range/CIDR via ICMP or ARP sweep/scan.
    :param ip_range: The IP range to scan.
    :param ping_method: The ping method to use.
    :returns: A list of dictionaries representing the hosts.
    """
    nm = nmap.PortScanner()

    # ping methods
    ping_flags = {
        'full': '-PE -PP -PR -PM',
        'arp': '-PR',
        'icmp': '-PE -PP -PM'
    }

    # ip_range at this point is literally the string taken from the --ip-range argument

    print(f"[*] Discovering hosts in {ip_range}...")
    nm.scan(hosts=ip_range, arguments=f"-sn -T5 {ping_flags[ping_method]}")

    os.makedirs('output', exist_ok=True)
    with open('output/output.xml', 'w') as f:
        f.write(str(nm.get_nmap_last_output()))

    # parse into a consistent format
    hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            host_info = {
                'address': host,
                'status': nm[host].state(),
                'hostname': nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else "(Unknown)",
                'mac': nm[host]['addresses'].get('mac', "(Unknown)") if 'mac' in nm[host]['addresses'] else "(Unknown)"
            }
            hosts.append(host_info)

    return hosts


def port_scan_ip(ip: str, aggressive: bool = False, scan_type: str = 'default') -> Dict[str, Any]:
    """
    Performs nmap scan on a given IP address based off predefined options.
    :param ip: The IP address to scan.
    :param aggressive: Boolean option to include -A argument.
    :param scan_type: Either 'default' or 'all-ports'. Default scans top1k, all-ports scans all ports.
    :returns: A dictionary representing the hosts.
    """
    output_file = f"output/{ip}.xml"

    args = "-sV -Pn -T5"

    if scan_type == 'all-ports':
        args += " -p-"

    if aggressive:
        args += " -A"

    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=ip, arguments=args, sudo=True)

        with open(output_file, 'w') as f:
            f.write(str(nm.get_nmap_last_output()))

        scan_result = {
            'ip': ip,
            'hostnames': nm[ip].hostnames() if ip in nm.all_hosts() else [],
            'status': nm[ip].state() if ip in nm.all_hosts() else 'unknown',
            'ports': [],
            'output_file': output_file
        }

        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    port_info = nm[ip][proto][port]
                    scan_result['ports'].append({
                        'port': port,
                        'protocol': proto,
                        'state': port_info['state'],
                        'service': port_info['name'],
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', '')
                    })

        return scan_result

    except Exception as e:
        print(f"[!] Error scanning {ip}: {str(e)}")
        return {
            'ip': ip,
            'error': str(e),
            'output_file': output_file
        }


def display_hosts(hosts: List[Dict[str, str]]) -> None:
    """
    Display discovered hosts in a formatted manner to the terminal.
    :param hosts: A list of dictionaries representing the hosts.
    :returns: None
    """
    print(f'\n[*] Found {len(hosts)} device(s) on network:')
    for host in hosts:
        # spacing for neat output
        ip_spacing = 8 - len(host['address'].split('.')[-1])
        mac_spacing = 5 if host['mac'] != '(Unknown)' else 13

        print(f"{host['address']}{' ' * ip_spacing}{host['mac']}{' ' * mac_spacing}{host['hostname']}")


def display_scan_results(results: List[Dict[str, Any]]) -> None:
    """
    Display the results of the scan to the terminal.
    :param results: A list of dictionaries representing the hosts.
    :returns: None
    """
    print("\n[*] Port scan results summary:")

    for result in results:
        print(f"\n[+] Host: {result['ip']}")

        if 'error' in result:
            print(f"    Error: {result['error']}")
            continue

        if not result.get('ports'):
            print("    No open ports found")
            continue

        print("    Open ports:")
        for port_info in result['ports']:
            if port_info['state'] == 'open':
                service_info = f"{port_info['service']}"
                if port_info.get('product'):
                    service_info += f" ({port_info['product']}"
                    if port_info.get('version'):
                        service_info += f" {port_info['version']}"
                    service_info += ")"

                print(f"    {port_info['port']}/{port_info['protocol']} - {service_info}")


def monitor_progress(active_scans: Set[str], timeout: int, stop_event: threading.Event) -> None:
    """
    Monitors ongoing port scans and reports if there has been no progress for specified timeout and displays in the terminal.
    :param active_scans: A set of active port scans.
    :param timeout: The timeout in seconds.
    :param stop_event: Thread to stop monitoring.
    :returns: None
    """
    """Monitor ongoing scans and report if no progress for specified timeout."""
    last_activity_time = time.time()

    while not stop_event.is_set():
        current_time = time.time()
        # if we haven't seen activity in more than the timeout period
        if current_time - last_activity_time > timeout and active_scans:
            print(f"[!] Still scanning:")
            for ip in active_scans:
                print(f"    - {ip}")
            # reset after reporting
            last_activity_time = current_time

        # checks for changes every 1 second
        if stop_event.wait(1.0):
            break

    print("[*] Progress monitoring stopped.")


def main() -> None:
    args = parse_args()
    os.makedirs('output', exist_ok=True)

    if ',' in args.ip_range:
        args.ip_range = args.ip_range.replace(', ', ' ')

    hosts = discover_hosts(args.ip_range, args.ping_method)

    if not hosts:
        print("[!] No hosts found. Exiting.")
        return

    display_hosts(hosts)

    # if port scanning is enabled
    if args.port_scan:
        print('\n[*] Running port scans...')
        ips = [host['address'] for host in hosts]
        total_ips = len(ips)
        completed_scans = 0
        scan_results = []

        # track active scans
        active_scans = set(ips)

        # event to signal when scanning is done
        stop_event = threading.Event()

        # monitoring thread
        monitor_thread = threading.Thread(
            target=monitor_progress,
            args=(active_scans, args.progress_timeout, stop_event)
        )
        monitor_thread.daemon = True
        monitor_thread.start()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
                future_to_ip = {
                    executor.submit(
                        port_scan_ip,
                        ip,
                        args.aggressive_port_scan,
                        args.port_scan
                    ): ip for ip in ips
                }

                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        scan_results.append(result)
                        completed_scans += 1
                        active_scans.remove(ip)
                        print(f"[+] Completed port scan for {ip} ({completed_scans}/{total_ips})")
                    except Exception as exc:
                        completed_scans += 1
                        active_scans.remove(ip)
                        print(f"[!] Scan for {ip} ({completed_scans}/{total_ips}) generated an exception: {exc}")
        finally:
            stop_event.set()
            monitor_thread.join(timeout=2.0)

        display_scan_results(scan_results)
        print("\n[*] All scans completed. Results saved in output directory.")


if __name__ == '__main__':
    main()