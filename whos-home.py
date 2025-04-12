import argparse
import subprocess

from libnmap.parser import NmapParser


def parse_args() -> argparse.Namespace:
    """
    Parses command line arguments.
    :return: The arguments parsed from the command line.
    """
    parser = argparse.ArgumentParser(description='LAN scanner')
    parser.add_argument('-i', '--ip-range', dest='ip_range', help='IP range(s) to scan', required=True)
    parser.add_argument('--nmap-scan', dest='nmap_scan',
                        choices=['default', 'all-ports'],
                        help='Perform Nmap scan: "default" (top 1000 ports) or "all-ports"')
    parser.add_argument('-A', '--aggressive-nmap-scan', dest='aggressive_nmap_scan',
                        help='Enable aggressive Nmap scan mode', action='store_true')
    parser.add_argument('--ping-method', dest='ping_method', choices=['icmp', 'arp', 'full'],
                        default='full', help='Specify the ping methods to use (default: full)')
    return parser.parse_args()


def run_command_no_output(command: str):
    """
    Runs the given bash command with no terminal output.
    :param command: Bash command to run.
    """
    try:
        subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True,
        )
    except:
        print(f"bash command failed {command}")


if __name__ == '__main__':
    args = parse_args()
    print('[*] Scanning now, please wait...')

    if args.ping_method == 'full':
        command = f'sudo nmap -sn -PE -PP -PR -PM {args.ip_range} -oX output.xml'
        run_command_no_output(command)
    elif args.ping_method == 'arp':
        command = f'sudo nmap -sn -PR {args.ip_range} -oX output.xml'
        run_command_no_output(command)
    elif args.ping_method == 'icmp':
        command = f'sudo nmap -sn -PE -PP -PM {args.ip_range} -oX output.xml'
        run_command_no_output(command)

    report = NmapParser.parse_fromfile('output.xml')
    if report.hosts:
        print(f'\n[*] Found {len(report.hosts)} device(s) at home:')
    for host in report.hosts:
        if host.hostnames:
            print(f'{host.address} {host.hostnames[0]}')
        else:
            print(host.address)
