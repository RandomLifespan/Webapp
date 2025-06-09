import os
import sqlite3
from datetime import datetime
import hashlib
import hmac
import secrets
import json # Import json for json.dumps

from functools import wraps
from flask import Flask, request, jsonify, render_template


app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')

# Database setup with more detailed schema
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection()
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            first_name TEXT,
            last_name TEXT,
            username TEXT,
            language_code TEXT,
            is_premium BOOLEAN,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            interactions INTEGER DEFAULT 1
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            referrer TEXT,
            created_at TEXT NOT NULL,
            last_activity TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
        ''')
        
        conn.execute('''
        CREATE TABLE IF NOT EXISTS user_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            event_data TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
        ''')
        conn.commit()
        conn.close()

# Initialize database
init_db()

# Security helper functions
def validate_telegram_data(init_data):
    try:
        # Parse the init_data string
        query_params = dict(qp.split('=', 1) for qp in init_data.split('&'))
        received_hash = query_params.pop('hash', None) # Extract and remove 'hash'

        if not received_hash:
            return False

        # Sort remaining parameters alphabetically and concatenate them
        # (excluding the 'user' parameter, as per your original logic)
        data_check_list = []
        for key, value in sorted(query_params.items()):
            if key != 'user': # Keep this line if you want to exclude 'user' from the hash check
                data_check_list.append(f"{key}={value}")
        data_check_string = '\n'.join(data_check_list)
        
        # The secret key for HMAC-SHA256 is the SHA256 hash of your bot token
        secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode()).digest()
        
        # Calculate the hash
        computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        
        # Compare the computed hash with the received hash
        return hmac.compare_digest(computed_hash, received_hash)
    except Exception as e:
        print(f"Telegram Data Validation Error: {e}") # Log the error for debugging
        return False

# Middleware to check Telegram authentication
@app.before_request
def check_telegram_authentication():
    # Define endpoints that DO NOT require Telegram authentication
    # Add 'admin_users' and all analytics endpoints to this list
    exempt_endpoints = [
        'index', 'static', 
        'admin_users', 
        'user_count', 'user_growth', 'top_events' # Analytics endpoints
    ]
    
    # Get the name of the endpoint Flask is trying to serve
    # request.endpoint is None for 404s, but here we expect valid endpoints
    if request.endpoint in exempt_endpoints:
        return # Skip Telegram authentication for these endpoints

    # All other endpoints require Telegram authentication
    telegram_init_data = request.headers.get('X-Telegram-Init-Data')
    
    if not telegram_init_data:
        return jsonify({'error': 'Unauthorized: Missing X-Telegram-Init-Data header'}), 401

    if not validate_telegram_data(telegram_init_data):
        return jsonify({'error': 'Unauthorized: Invalid Telegram data'}), 401
    
    # If validation passes, continue with the request
    return

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_user_info', methods=['POST'])
def get_user_info():
    data = request.json
    now = datetime.now().isoformat()
    
    if not data or 'user' not in data:
        return jsonify({'error': 'Invalid data: "user" key missing'}), 400
    
    user_data = data['user']
    
    try:
        conn = get_db_connection()
        
        # Track session
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent')
        referrer = request.headers.get('Referer')
        
        # Upsert user data
        conn.execute('''
        INSERT INTO users 
            (user_id, first_name, last_name, username, language_code, is_premium, created_at, last_seen, interactions)
        VALUES 
            (?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(user_id) DO UPDATE SET
            first_name = excluded.first_name,
            last_name = excluded.last_name,
            username = excluded.username,
            language_code = excluded.language_code,
            is_premium = excluded.is_premium,
            last_seen = ?,
            interactions = interactions + 1
        ''', (
            user_data['id'],
            user_data.get('first_name'),
            user_data.get('last_name'),
            user_data.get('username'),
            user_data.get('language_code'),
            user_data.get('is_premium', False),
            now, # created_at for new user
            now  # last_seen updated for existing/new user
        ))
        
        # Record session
        session_id = hashlib.sha256(f"{user_data['id']}{now}{secrets.token_hex(8)}".encode()).hexdigest()
        conn.execute('''
        INSERT INTO user_sessions 
            (session_id, user_id, ip_address, user_agent, referrer, created_at, last_activity)
        VALUES 
            (?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            user_data['id'],
            ip,
            user_agent,
            referrer,
            now,
            now
        ))
        
        # Record event
        conn.execute('''
        INSERT INTO user_events 
            (user_id, event_type, event_data, created_at)
        VALUES 
            (?, ?, ?, ?)
        ''', (
            user_data['id'],
            'mini_app_launch',
            json.dumps({
                'source': 'telegram_mini_app',
                'user_agent': user_agent
            }),
            now
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'user_id': user_data['id'],
            'first_name': user_data.get('first_name'),
            'last_name': user_data.get('last_name'),
            'username': user_data.get('username')
        })
    
    except Exception as e:
        # Proper error handling and logging
        print(f"Error in get_user_info: {e}")
        return jsonify({'error': str(e)}), 500

# Analytics Endpoints
# These endpoints will now be exempt from Telegram auth by the updated before_request
@app.route('/analytics/users/count')
def user_count():
    try:
        conn = get_db_connection()
        total = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        today = conn.execute('''
            SELECT COUNT(*) FROM users 
            WHERE DATE(last_seen) = DATE('now')
        ''').fetchone()[0]
        conn.close()
        return jsonify({'total_users': total, 'active_today': today})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analytics/users/growth')
def user_growth():
    try:
        conn = get_db_connection()
        growth = conn.execute('''
            SELECT DATE(created_at) as date, COUNT(*) as new_users
            FROM users
            GROUP BY DATE(created_at)
            ORDER BY date DESC
            LIMIT 30
        ''').fetchall()
        conn.close()
        return jsonify([dict(row) for row in growth])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analytics/events/top')
def top_events():
    try:
        conn = get_db_connection()
        events = conn.execute('''
            SELECT event_type, COUNT(*) as count
            FROM user_events
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 10
        ''').fetchall()
        conn.close()
        return jsonify([dict(row) for row in events])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin protection middleware
def require_admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_admin_credentials(auth.username, auth.password):
            return 'Could not verify your access level for that URL.\n' \
                   'You have to login with proper credentials', 401, \
                   {'WWW-Authenticate': 'Basic realm="Login Required"'}
        return f(*args, **kwargs)
    return decorated    

def check_admin_credentials(username, password):
    # In production, use proper password hashing and environment variables
    # On Railway, you'll set ADMIN_USERNAME and ADMIN_PASSWORD in your project variables
    correct_username = os.environ.get('ADMIN_USERNAME', 'admin')
    correct_password = os.environ.get('ADMIN_PASSWORD', 'securepassword')
    return username == correct_username and password == correct_password

@app.route('/admin/users')
@require_admin_auth # This decorator will now correctly handle authentication
def admin_users():
    try:
        conn = get_db_connection()
        users_raw = conn.execute('SELECT * FROM users ORDER BY last_seen DESC LIMIT 100').fetchall()
        conn.close()
        users = [dict(user) for user in users_raw]
        return render_template('admin.html', users=users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
