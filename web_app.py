# web_app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import threading
import argparse
import datetime
from database import ScanDatabase
import nmap_scanner  # We'll create this next

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production
db = ScanDatabase()


@app.context_processor
def inject_current_year():
    """Inject the current year into all templates."""
    return {'current_year': datetime.datetime.now().year}


@app.template_filter('datetime')
def format_datetime(value):
    """Format ISO datetime strings to readable format."""
    try:
        dt = datetime.datetime.fromisoformat(value)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return value


@app.route('/')
def index():
    """Home page - show recent scans."""
    scans = db.get_scans()
    return render_template('index.html', scans=scans)


@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    """View detailed results for a specific scan."""
    try:
        scan_results = db.get_scan_results(scan_id)
        return render_template('scan_details.html', scan=scan_results)
    except Exception as e:
        flash(f"Error retrieving scan: {str(e)}")
        return redirect(url_for('index'))


@app.route('/new_scan', methods=['GET', 'POST'])
def new_scan():
    """Form to start a new scan."""
    if request.method == 'POST':
        ip_range = request.form.get('ip_range')
        ping_method = request.form.get('ping_method', 'full')
        port_scan = request.form.get('port_scan')
        aggressive = True if request.form.get('aggressive_scan') else False

        if not ip_range:
            flash("IP range is required")
            return redirect(url_for('new_scan'))

        # Start scan in background thread
        scan_thread = threading.Thread(
            target=nmap_scanner.run_scan_from_web,
            args=(ip_range, ping_method, port_scan, aggressive)
        )
        scan_thread.daemon = True
        scan_thread.start()

        flash("Scan started! Results will be available once complete.")
        return redirect(url_for('index'))

    return render_template('new_scan.html')


@app.route('/api/scans')
def api_scans():
    """API endpoint to get all scans."""
    scans = db.get_scans()
    return jsonify(scans)


@app.route('/api/scan/<int:scan_id>')
def api_scan(scan_id):
    """API endpoint to get details of a specific scan."""
    scan = db.get_scan_results(scan_id)
    return jsonify(scan)


def start_web_server(host='0.0.0.0', port=5000, debug=False):
    """Start the Flask web server."""
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Network Scanner Web Interface')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')

    args = parser.parse_args()
    start_web_server(args.host, args.port, args.debug)