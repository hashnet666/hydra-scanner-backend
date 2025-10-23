from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import time
import random
import uuid
from datetime import datetime, timedelta
import logging
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure CORS to only allow your Cloudflare Pages domain
CORS(app, origins=[
    "https://hydra-scanner.pages.dev",
    "http://localhost:3000",  # For local development
])

# Store active scans with user sessions
active_scans = {}
user_sessions = {}

# Rate limiting
request_counts = {}

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        now = time.time()
        
        # Clean old entries
        request_counts[client_ip] = [t for t in request_counts.get(client_ip, []) if now - t < 3600]
        
        # Check rate limit (100 requests per hour per IP)
        if len(request_counts.get(client_ip, [])) >= 100:
            return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
        
        request_counts.setdefault(client_ip, []).append(now)
        return f(*args, **kwargs)
    return decorated_function

def create_user_session():
    """Create a new user session"""
    session_id = str(uuid.uuid4())
    user_sessions[session_id] = {
        'created_at': datetime.now(),
        'last_activity': datetime.now(),
        'scans_created': 0,
        'active_scans': []
    }
    return session_id

def validate_session(session_id):
    """Validate and update user session"""
    if session_id not in user_sessions:
        return False
    
    # Update last activity
    user_sessions[session_id]['last_activity'] = datetime.now()
    
    # Clean up old sessions (24 hours)
    if datetime.now() - user_sessions[session_id]['created_at'] > timedelta(hours=24):
        del user_sessions[session_id]
        return False
    
    return True

def cleanup_old_data():
    """Clean up old scans and sessions"""
    current_time = datetime.now()
    
    # Remove scans older than 1 hour
    expired_scans = []
    for scan_id, scan_data in active_scans.items():
        if current_time - scan_data.get('created_at', current_time) > timedelta(hours=1):
            expired_scans.append(scan_id)
    
    for scan_id in expired_scans:
        del active_scans[scan_id]
    
    # Remove sessions older than 24 hours
    expired_sessions = []
    for session_id, session_data in user_sessions.items():
        if current_time - session_data['created_at'] > timedelta(hours=24):
            expired_sessions.append(session_id)
    
    for session_id in expired_sessions:
        del user_sessions[session_id]

@app.route('/')
@rate_limit
def home():
    cleanup_old_data()
    return jsonify({
        "status": "Hydra Scanner API", 
        "version": "2.0",
        "users_active": len(user_sessions),
        "scans_active": len(active_scans),
        "message": "Backend is running with enhanced security"
    })

@app.route('/session', methods=['GET'])
@rate_limit
def create_session():
    """Create a new user session"""
    session_id = create_user_session()
    return jsonify({
        'session_id': session_id,
        'message': 'Session created successfully'
    })

@app.route('/scan', methods=['POST'])
@rate_limit
def start_scan():
    """Start a new scan with session management"""
    try:
        data = request.json
        hosts = data.get('hosts', [])
        protocol = data.get('protocol', 'http')
        session_id = data.get('session_id')
        
        # Validate session
        if not session_id or not validate_session(session_id):
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        # Validate input
        if not hosts or not protocol:
            return jsonify({'error': 'Missing hosts or protocol'}), 400
        
        if len(hosts) > 1000:  # Limit hosts per scan
            return jsonify({'error': 'Too many hosts. Maximum 1000 per scan.'}), 400
        
        # Create scan
        scan_id = f"scan_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Initialize scan data
        active_scans[scan_id] = {
            'status': 'running',
            'hosts': hosts,
            'protocol': protocol,
            'results': [],
            'tunneled_hosts': [],
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'current_host': None,
            'session_id': session_id,
            'created_at': datetime.now(),
            'start_time': time.time()
        }
        
        # Add to user session
        user_sessions[session_id]['active_scans'].append(scan_id)
        user_sessions[session_id]['scans_created'] += 1
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_scan, 
            args=(scan_id, hosts, protocol, session_id)
        )
        thread.daemon = True
        thread.start()
        
        logger.info(f"Scan started: {scan_id} for session: {session_id}")
        
        return jsonify({
            'scan_id': scan_id, 
            'status': 'started',
            'total_hosts': len(hosts),
            'protocol': protocol,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/<scan_id>')
@rate_limit
def get_scan(scan_id):
    """Get scan status and results"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_data = active_scans[scan_id]
    
    response_data = {
        'scan_id': scan_id,
        'status': scan_data['status'],
        'processed': scan_data['processed'],
        'total': len(scan_data['hosts']),
        'successful': scan_data['successful'],
        'failed': scan_data['failed'],
        'results': scan_data['results'],
        'tunneled_hosts': scan_data['tunneled_hosts'],
        'current_host': scan_data['current_host'],
        'protocol': scan_data['protocol'],
        'progress': (scan_data['processed'] / len(scan_data['hosts'])) * 100 if scan_data['hosts'] else 0
    }
    
    # Add duration if completed
    if scan_data['status'] == 'completed':
        response_data['duration'] = time.time() - scan_data['start_time']
    
    return jsonify(response_data)

@app.route('/scan/<scan_id>', methods=['DELETE'])
@rate_limit
def cancel_scan(scan_id):
    """Cancel a scan"""
    if scan_id in active_scans:
        # Remove from user session
        session_id = active_scans[scan_id].get('session_id')
        if session_id and session_id in user_sessions:
            user_sessions[session_id]['active_scans'] = [
                s for s in user_sessions[session_id]['active_scans'] 
                if s != scan_id
            ]
        
        del active_scans[scan_id]
        logger.info(f"Scan cancelled: {scan_id}")
        return jsonify({'status': 'cancelled', 'message': 'Scan cancelled successfully'})
    
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/user/<session_id>/scans')
@rate_limit
def get_user_scans(session_id):
    """Get all scans for a user session"""
    if not validate_session(session_id):
        return jsonify({'error': 'Invalid session'}), 401
    
    user_scans = []
    for scan_id in user_sessions[session_id].get('active_scans', []):
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
            user_scans.append({
                'scan_id': scan_id,
                'status': scan_data['status'],
                'protocol': scan_data['protocol'],
                'processed': scan_data['processed'],
                'total': len(scan_data['hosts']),
                'successful': scan_data['successful'],
                'created_at': scan_data['created_at'].isoformat()
            })
    
    return jsonify({
        'session_id': session_id,
        'scans_created': user_sessions[session_id]['scans_created'],
        'active_scans': user_scans
    })

def run_scan(scan_id, hosts, protocol, session_id):
    """Run the actual scan simulation"""
    try:
        for i, host in enumerate(hosts):
            # Check if scan was cancelled
            if scan_id not in active_scans or active_scans[scan_id]['status'] == 'cancelled':
                break
            
            # Update current host being processed
            active_scans[scan_id]['current_host'] = host
            
            # Simulate network delay
            time.sleep(0.3 + random.random() * 0.7)
            
            # Simulate scan result with realistic probabilities
            is_success = simulate_host_scan(host, protocol)
            is_tunneled = is_success and random.random() > 0.3  # 70% of successful hosts are tunneled
            
            # Update scan progress
            active_scans[scan_id]['processed'] = i + 1
            
            if is_success:
                active_scans[scan_id]['successful'] += 1
                active_scans[scan_id]['results'].append(host)
                
                if is_tunneled:
                    active_scans[scan_id]['tunneled_hosts'].append({
                        'host': host,
                        'protocol': protocol,
                        'tunnel_type': get_tunnel_type(protocol),
                        'timestamp': datetime.now().isoformat()
                    })
            else:
                active_scans[scan_id]['failed'] += 1
        
        # Mark scan as completed if not cancelled
        if scan_id in active_scans and active_scans[scan_id]['status'] != 'cancelled':
            active_scans[scan_id]['status'] = 'completed'
            active_scans[scan_id]['current_host'] = None
            
            # Remove from user's active scans
            if session_id in user_sessions:
                user_sessions[session_id]['active_scans'] = [
                    s for s in user_sessions[session_id]['active_scans'] 
                    if s != scan_id
                ]
            
            logger.info(f"Scan completed: {scan_id} - {active_scans[scan_id]['successful']}/{len(hosts)} successful")
    
    except Exception as e:
        logger.error(f"Error in scan {scan_id}: {str(e)}")
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'error'
            active_scans[scan_id]['error'] = str(e)

def simulate_host_scan(host, protocol):
    """Simulate scanning a host with protocol-specific success rates"""
    success_rates = {
        'http': 0.45,
        'tls': 0.40,
        'vless': 0.35,
        'cloudfront_tls': 0.30,
        'dynamic_tls': 0.25
    }
    
    success_rate = success_rates.get(protocol, 0.3)
    
    # Add some randomness based on host characteristics
    if '.cloudfront.net' in host:
        success_rate += 0.1
    if 'cdn' in host or 'proxy' in host:
        success_rate += 0.05
    
    return random.random() < success_rate

def get_tunnel_type(protocol):
    """Get tunnel type description"""
    tunnel_types = {
        'http': 'HTTP Tunnel',
        'tls': 'TLS/SSL Tunnel', 
        'vless': 'VLESS Proxy',
        'cloudfront_tls': 'CloudFront CDN',
        'dynamic_tls': 'Dynamic TLS'
    }
    return tunnel_types.get(protocol, 'Unknown Tunnel')

# Background cleanup task
def background_cleanup():
    while True:
        time.sleep(300)  # Run every 5 minutes
        try:
            cleanup_old_data()
            logger.info("Background cleanup completed")
        except Exception as e:
            logger.error(f"Error in background cleanup: {str(e)}")

# Start background cleanup thread
cleanup_thread = threading.Thread(target=background_cleanup)
cleanup_thread.daemon = True
cleanup_thread.start()

if __name__ == '__main__':
    logger.info("Starting Hydra Scanner Backend with enhanced features")
    app.run(host='0.0.0.0', port=5000, debug=False)
