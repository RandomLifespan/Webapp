from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, g
import os
import psycopg2 # Changed from sqlite3 to psycopg2
from psycopg2 import extras # For dictionary-like row access
from datetime import datetime, timedelta
import hashlib
import hmac
import secrets
import urllib.parse
import json

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['TELEGRAM_BOT_TOKEN'] = os.environ.get('TELEGRAM_BOT_TOKEN', '')

# --- PostgreSQL Database Connection ---
def get_db_connection():
    try:
        # Railway automatically provides the DATABASE_URL environment variable
        # for your PostgreSQL service.
        db_url = os.environ.get('DATABASE_URL')
        if not db_url:
            raise ValueError("DATABASE_URL environment variable is not set.")

        conn = psycopg2.connect(db_url)
        # Use RealDictCursor to get dictionary-like rows
        # This makes row['column_name'] work similar to sqlite3.Row
        return conn
    except Exception as e:
        print(f"Error connecting to PostgreSQL database: {e}")
        # Depending on your error handling strategy, you might want to re-raise or return None
        raise

def init_db():
    with app.app_context():
        conn = None # Initialize conn to None
        try:
            conn = get_db_connection()
            cur = conn.cursor() # Get a cursor for executing commands
            
            # Use cursor.execute for DDL statements
            cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, -- SERIAL for auto-incrementing integer PK
                user_id BIGINT NOT NULL UNIQUE, -- BIGINT for Telegram user_id
                first_name TEXT,
                last_name TEXT,
                username TEXT,
                language_code TEXT,
                is_premium BOOLEAN,
                created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, -- TIMESTAMP for datetime
                last_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                interactions INTEGER DEFAULT 1
            );
            ''')
            
            cur.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                user_id BIGINT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                referrer TEXT,
                created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                last_activity TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            );
            ''')
            
            cur.execute('''
            CREATE TABLE IF NOT EXISTS user_events (
                event_id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT,
                created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            );
            ''')
            conn.commit()
            print("PostgreSQL tables checked/created successfully.")
        except Exception as e:
            print(f"Error initializing PostgreSQL database: {e}")
            if conn:
                conn.rollback() # Rollback on error
        finally:
            if conn:
                conn.close()

# Initialize database
init_db()

# --- Security helper functions (remain largely the same) ---
def validate_telegram_data(init_data_raw):
    if not app.config['TELEGRAM_BOT_TOKEN']:
        print("TELEGRAM_BOT_TOKEN is not set in app.config!")
        return False

    params = urllib.parse.parse_qs(init_data_raw)
    data_check_string_parts = []
    hash_value = None

    for key, value in sorted(params.items()):
        current_value = value[0] if isinstance(value, list) else value
        
        if key == 'hash':
            hash_value = current_value
        else:
            data_check_string_parts.append(f"{key}={current_value}")

    data_check_string = '\n'.join(data_check_string_parts)

    if not hash_value:
        print("Hash value not found in init_data.")
        return False

    secret_key = hmac.new(
        key="WebAppData".encode('utf-8'),
        msg=app.config['TELEGRAM_BOT_TOKEN'].encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()

    calculated_hash = hmac.new(
        key=secret_key,
        msg=data_check_string.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(calculated_hash, hash_value):
        print(f"Validation failed: Calculated hash {calculated_hash} != Provided hash {hash_value}")
        return False
    
    auth_date_str = params.get('auth_date', [None])[0]
    if auth_date_str:
        try:
            auth_date = datetime.fromtimestamp(int(auth_date_str))
            if datetime.now() - auth_date > timedelta(seconds=3600):
                print("Telegram init_data is too old.")
                return False
        except ValueError:
            print("Invalid auth_date format.")
            return False

    return True

# --- Middleware for Telegram Authentication ---
@app.before_request
def check_telegram_authentication():
    exempt_endpoints = [
        'index', 'static', 'admin_users', 
        'user_count', 'user_growth', 'top_events' 
    ]
    
    if request.endpoint in exempt_endpoints:
        return 

    telegram_init_data = request.headers.get('X-Telegram-Init-Data')
    
    if not telegram_init_data:
        return jsonify({'error': 'Unauthorized: Missing X-Telegram-Init-Data header'}), 401

    if not validate_telegram_data(telegram_init_data):
        return jsonify({'error': 'Unauthorized: Invalid Telegram data'}), 401
    
    return

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_user_info', methods=['POST'])
def get_user_info():
    data = request.json
    now = datetime.now() # Get datetime object directly for PostgreSQL
    
    if not data or 'user' not in data:
        return jsonify({'error': 'Invalid data: "user" key missing'}), 400
    
    user_data = data['user']
    
    conn = None # Initialize conn to None
    try:
        conn = get_db_connection()
        cur = conn.cursor() # Get a cursor
        
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent')
        referrer = request.headers.get('Referer')
        
        # PostgreSQL UPSERT (INSERT ... ON CONFLICT)
        cur.execute('''
        INSERT INTO users 
            (user_id, first_name, last_name, username, language_code, is_premium, created_at, last_seen, interactions)
        VALUES 
            (%s, %s, %s, %s, %s, %s, %s, %s, 1)
        ON CONFLICT(user_id) DO UPDATE SET
            first_name = EXCLUDED.first_name,
            last_name = EXCLUDED.last_name,
            username = EXCLUDED.username,
            language_code = EXCLUDED.language_code,
            is_premium = EXCLUDED.is_premium,
            last_seen = %s, -- Only last_seen is updated from current timestamp
            interactions = users.interactions + 1
        ''', (
            user_data['id'],
            user_data.get('first_name'),
            user_data.get('last_name'),
            user_data.get('username'),
            user_data.get('language_code'),
            user_data.get('is_premium', False),
            now, # created_at for new user
            now, # last_seen for new user
            now  # last_seen for existing user in DO UPDATE SET
        ))
        
        session_id = hashlib.sha256(f"{user_data['id']}{now}{secrets.token_hex(8)}".encode()).hexdigest()
        cur.execute('''
        INSERT INTO user_sessions 
            (session_id, user_id, ip_address, user_agent, referrer, created_at, last_activity)
        VALUES 
            (%s, %s, %s, %s, %s, %s, %s)
        ''', (
            session_id,
            user_data['id'],
            ip,
            user_agent,
            referrer,
            now,
            now
        ))
        
        cur.execute('''
        INSERT INTO user_events 
            (user_id, event_type, event_data, created_at)
        VALUES 
            (%s, %s, %s, %s)
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
        
        return jsonify({
            'status': 'success',
            'user_id': user_data['id'],
            'first_name': user_data.get('first_name'),
            'last_name': user_data.get('last_name'),
            'username': user_data.get('username')
        })
    
    except Exception as e:
        print(f"Error in get_user_info: {e}")
        if conn:
            conn.rollback() # Rollback on error
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

# --- Analytics Endpoints (updated to use cursor and fetchall) ---
@app.route('/analytics/users/count')
def user_count():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM users')
        total = cur.fetchone()[0]
        cur.execute('''
            SELECT COUNT(*) FROM users 
            WHERE DATE(last_seen) = CURRENT_DATE
        ''') # PostgreSQL CURRENT_DATE
        today = cur.fetchone()[0]
        return jsonify({'total_users': total, 'active_today': today})
    except Exception as e:
        print(f"Error in user_count: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/analytics/users/growth')
def user_growth():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) # Use RealDictCursor for dict-like rows
        cur.execute('''
            SELECT CAST(created_at AS DATE) as date, COUNT(*) as new_users
            FROM users
            GROUP BY CAST(created_at AS DATE)
            ORDER BY date DESC
            LIMIT 30
        ''')
        growth = cur.fetchall()
        return jsonify([dict(row) for row in growth]) # Convert RealDictRow to dict if needed for jsonify
    except Exception as e:
        print(f"Error in user_growth: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/analytics/events/top')
def top_events():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) # Use RealDictCursor for dict-like rows
        cur.execute('''
            SELECT event_type, COUNT(*) as count
            FROM user_events
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 10
        ''')
        events = cur.fetchall()
        return jsonify([dict(row) for row in events])
    except Exception as e:
        print(f"Error in top_events: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

# --- Admin protection middleware ---
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
    correct_username = os.environ.get('ADMIN_USERNAME', 'admin')
    correct_password = os.environ.get('ADMIN_PASSWORD', 'securepassword')
    return username == correct_username and password == correct_password

@app.route('/admin/users')
@require_admin_auth 
def admin_users():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) # Use RealDictCursor
        cur.execute('SELECT * FROM users ORDER BY last_seen DESC LIMIT 100')
        users_raw = cur.fetchall()
        # RealDictCursor already provides dict-like rows, so direct conversion is clean
        users = [dict(user) for user in users_raw] 
        return render_template('admin.html', users=users)
    except Exception as e:
        print(f"Error fetching admin users: {e}")
        return jsonify({'error': 'Failed to retrieve user data: ' + str(e)}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # It's good practice to call init_db() when the app starts
    # to ensure tables exist.
    init_db() 
    app.run(host='0.0.0.0', port=port, debug=True)
