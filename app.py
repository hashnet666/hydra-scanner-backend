from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import time
import random

app = Flask(__name__)
CORS(app)

# Store active scans
active_scans = {}

@app.route('/')
def home():
    return jsonify({"status": "Hydra Scanner API", "version": "2.0"})

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    hosts = data.get('hosts', [])
    protocol = data.get('protocol', 'http')
    
    scan_id = f"scan_{int(time.time())}"
    
    # Start scan in background thread
    thread = threading.Thread(target=simulate_scan, args=(scan_id, hosts, protocol))
    thread.daemon = True
    thread.start()
    
    active_scans[scan_id] = {
        'status': 'running',
        'progress': 0,
        'results': [],
        'hosts': hosts
    }
    
    return jsonify({'scan_id': scan_id, 'status': 'started'})

@app.route('/scan/<scan_id>')
def get_scan(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(active_scans[scan_id])

@app.route('/scan/<scan_id>', methods=['DELETE'])
def cancel_scan(scan_id):
    if scan_id in active_scans:
        del active_scans[scan_id]
        return jsonify({'status': 'cancelled'})
    return jsonify({'error': 'Scan not found'}), 404

def simulate_scan(scan_id, hosts, protocol):
    """Simulate scanning process"""
    total = len(hosts)
    
    for i, host in enumerate(hosts):
        if scan_id not in active_scans:
            break
            
        # Simulate network delay
        time.sleep(0.5 + random.random())
        
        # Simulate success (40% chance)
        is_success = random.random() > 0.6
        
        if is_success:
            active_scans[scan_id]['results'].append(host)
        
        # Update progress
        progress = ((i + 1) / total) * 100
        active_scans[scan_id]['progress'] = progress
        active_scans[scan_id]['processed'] = i + 1
        active_scans[scan_id]['successful'] = len(active_scans[scan_id]['results'])
    
    if scan_id in active_scans:
        active_scans[scan_id]['status'] = 'completed'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)