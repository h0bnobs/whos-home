import os
import sqlite3
import datetime
from typing import Dict, Any, List


class ScanDatabase:
    def __init__(self, db_path='scanner.db'):
        """Initialize the database connection."""
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self.init_db()

    def connect(self):
        """Establish a connection to the database."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None

    def init_db(self):
        """Initialize the database schema if it doesn't exist."""
        self.connect()

        # Create scans table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_range TEXT NOT NULL,
            ping_method TEXT NOT NULL,
            scan_type TEXT,
            aggressive BOOLEAN,
            completed BOOLEAN DEFAULT 0
        )
        ''')

        # Create hosts table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            address TEXT NOT NULL,
            status TEXT NOT NULL,
            hostname TEXT,
            mac TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        ''')

        # Create ports table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        )
        ''')

        self.conn.commit()
        self.close()

    def create_scan(self, ip_range: str, ping_method: str, scan_type: str = None, aggressive: bool = False) -> int:
        """Create a new scan record and return its ID."""
        self.connect()
        timestamp = datetime.datetime.now().isoformat()

        self.cursor.execute('''
        INSERT INTO scans (timestamp, ip_range, ping_method, scan_type, aggressive)
        VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, ip_range, ping_method, scan_type, aggressive))

        scan_id = self.cursor.lastrowid
        self.conn.commit()
        self.close()
        return scan_id

    def save_hosts(self, scan_id: int, hosts: List[Dict[str, str]]) -> List[int]:
        """Save discovered hosts to the database."""
        self.connect()
        host_ids = []

        for host in hosts:
            self.cursor.execute('''
            INSERT INTO hosts (scan_id, address, status, hostname, mac)
            VALUES (?, ?, ?, ?, ?)
            ''', (
                scan_id,
                host['address'],
                host.get('status', 'up'),
                host.get('hostname', '(Unknown)'),
                host.get('mac', '(Unknown)')
            ))
            host_ids.append(self.cursor.lastrowid)

        self.conn.commit()
        self.close()
        return host_ids

    def save_port_results(self, host_id: int, ports: List[Dict[str, Any]]) -> None:
        """Save port scan results to the database."""
        if not ports:
            return

        self.connect()

        for port_info in ports:
            self.cursor.execute('''
            INSERT INTO ports (host_id, port, protocol, state, service, product, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                host_id,
                port_info['port'],
                port_info['protocol'],
                port_info['state'],
                port_info.get('service', ''),
                port_info.get('product', ''),
                port_info.get('version', '')
            ))

        self.conn.commit()
        self.close()

    def mark_scan_complete(self, scan_id: int) -> None:
        """Mark a scan as completed."""
        self.connect()
        self.cursor.execute('''
        UPDATE scans SET completed = 1 WHERE id = ?
        ''', (scan_id,))
        self.conn.commit()
        self.close()

    def get_scans(self) -> List[Dict[str, Any]]:
        """Retrieve all scans from the database."""
        self.connect()
        self.cursor.execute('''
        SELECT * FROM scans ORDER BY timestamp DESC
        ''')
        scans = [dict(row) for row in self.cursor.fetchall()]
        self.close()
        return scans

    def get_scan(self, scan_id: int) -> Dict[str, Any]:
        """Retrieve a specific scan by ID."""
        self.connect()
        self.cursor.execute('''
        SELECT * FROM scans WHERE id = ?
        ''', (scan_id,))
        scan = dict(self.cursor.fetchone())
        self.close()
        return scan

    def get_hosts_for_scan(self, scan_id: int) -> List[Dict[str, Any]]:
        """Retrieve all hosts for a specific scan."""
        self.connect()
        self.cursor.execute('''
        SELECT * FROM hosts WHERE scan_id = ?
        ''', (scan_id,))
        hosts = [dict(row) for row in self.cursor.fetchall()]
        self.close()
        return hosts

    def get_ports_for_host(self, host_id: int) -> List[Dict[str, Any]]:
        """Retrieve all ports for a specific host."""
        self.connect()
        self.cursor.execute('''
        SELECT * FROM ports WHERE host_id = ? ORDER BY port
        ''', (host_id,))
        ports = [dict(row) for row in self.cursor.fetchall()]
        self.close()
        return ports

    def get_scan_results(self, scan_id: int) -> Dict[str, Any]:
        """Get comprehensive results for a scan including hosts and ports."""
        scan = self.get_scan(scan_id)
        hosts = self.get_hosts_for_scan(scan_id)

        for host in hosts:
            host['ports'] = self.get_ports_for_host(host['id'])

        scan['hosts'] = hosts
        scan['host_count'] = len(hosts)

        # Calculate open port count
        open_port_count = 0
        for host in hosts:
            open_port_count += sum(1 for port in host['ports'] if port['state'] == 'open')

        scan['open_port_count'] = open_port_count

        return scan