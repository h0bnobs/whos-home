import argparse
import concurrent.futures
import os
import sys
import threading
import time
from typing import List, Dict, Any, Set

import nmap
from database import ScanDatabase


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

    parser.add_argument('--web', action='store_true', help='Run the web interface')
    parser.add_argument('--web-host', default='0.0.0.0', help='Web interface host')
    parser.add_argument('--web-port', type=int, default=5000, help='Web interface port')

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


def run_scan_from_web(ip_range: str, ping_method: str = 'full', port_scan: str = None, aggressive: bool = False) -> int:
    """Run a scan initiated from the web interface and save results to database."""
    print(f"[*] Starting scan from web interface: {ip_range}")
    db = ScanDatabase()

    # Create scan record
    scan_id = db.create_scan(ip_range, ping_method, port_scan, aggressive)

    try:
        # Discover hosts
        hosts = discover_hosts(ip_range, ping_method)

        # Save hosts to database
        host_ids_map = {}  # Maps IP addresses to database host IDs
        if hosts:
            host_ids = db.save_hosts(scan_id, hosts)
            for i, host in enumerate(hosts):
                host_ids_map[host['address']] = host_ids[i]

        # Run port scans if requested
        if port_scan and hosts:
            ips = [host['address'] for host in hosts]

            # Configure scan parameters
            scan_results = []
            active_scans = set(ips)
            stop_event = threading.Event()

            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=monitor_progress,
                args=(active_scans, 60, stop_event)
            )
            monitor_thread.daemon = True
            monitor_thread.start()

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=14) as executor:
                    future_to_ip = {
                        executor.submit(
                            port_scan_ip,
                            ip,
                            aggressive,
                            port_scan
                        ): ip for ip in ips
                    }

                    for future in concurrent.futures.as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            result = future.result()
                            scan_results.append(result)
                            active_scans.remove(ip)

                            # Save port results to database
                            if result.get('ports') and ip in host_ids_map:
                                db.save_port_results(host_ids_map[ip], result['ports'])

                            print(f"[+] Completed port scan for {ip}")
                        except Exception as exc:
                            active_scans.remove(ip)
                            print(f"[!] Scan for {ip} generated an exception: {exc}")
            finally:
                stop_event.set()
                monitor_thread.join(timeout=2.0)

        # Mark scan as complete
        db.mark_scan_complete(scan_id)
        print(f"[*] Scan {scan_id} completed and saved to database")
        return scan_id

    except Exception as e:
        print(f"[!] Error during scan: {str(e)}")
        return scan_id


def main() -> None:
    args = parse_args()
    os.makedirs('output', exist_ok=True)

    # If --web is specified, start the web interface
    if args.web:
        from web_app import start_web_server
        print(f"[*] Starting web interface on {args.web_host}:{args.web_port}")
        start_web_server(args.web_host, args.web_port)
        return

    # Otherwise, run a CLI scan as before
    if ',' in args.ip_range:
        args.ip_range = args.ip_range.replace(', ', ' ')

    hosts = discover_hosts(args.ip_range, args.ping_method)

    if not hosts:
        print("[!] No hosts found. Exiting.")
        return

    display_hosts(hosts)

    # Connect to database
    db = ScanDatabase()

    # Create scan record
    scan_id = db.create_scan(
        args.ip_range,
        args.ping_method,
        args.port_scan if args.port_scan else None,
        args.aggressive_port_scan
    )

    # Save hosts to database
    host_ids_map = {}  # Maps IP addresses to database host IDs
    host_ids = db.save_hosts(scan_id, hosts)
    for i, host in enumerate(hosts):
        host_ids_map[host['address']] = host_ids[i]

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

                        # Save port results to database
                        if result.get('ports') and ip in host_ids_map:
                            db.save_port_results(host_ids_map[ip], result['ports'])

                    except Exception as exc:
                        completed_scans += 1
                        active_scans.remove(ip)
                        print(f"[!] Scan for {ip} ({completed_scans}/{total_ips}) generated an exception: {exc}")
        finally:
            stop_event.set()
            monitor_thread.join(timeout=2.0)

        display_scan_results(scan_results)
        print("\n[*] All scans completed. Results saved in output directory.")

    # Mark scan as complete
    db.mark_scan_complete(scan_id)
    print(f"[*] Scan results also saved to database with ID: {scan_id}")
    print(f"[*] Start the web interface with 'python nmap_scanner.py --web' to view results")


if __name__ == '__main__':
    main()