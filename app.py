from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, g
import os
import psycopg2
from psycopg2 import extras # Needed for RealDictCursor
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
        db_url = os.environ.get('DATABASE_URL')
        if not db_url:
            print("DATABASE_URL environment variable is not set. Cannot connect to DB.")
            raise ValueError("DATABASE_URL environment variable is not set.")

        conn = psycopg2.connect(db_url)
        return conn
    except Exception as e:
        print(f"Error connecting to PostgreSQL database: {e}")
        # Re-raise to ensure the error propagates and is caught by the route's try-except
        raise

def init_db():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL UNIQUE,
            first_name TEXT,
            last_name TEXT,
            username TEXT,
            language_code TEXT,
            is_premium BOOLEAN,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
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
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
        );
        ''')
        
        cur.execute('''
        CREATE TABLE IF NOT EXISTS user_events (
            event_id SERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL,
            event_type TEXT NOT NULL,
            event_data JSONB,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
        );
        ''')
        conn.commit()
        print("PostgreSQL tables checked/created successfully.")
    except Exception as e:
        print(f"Error initializing PostgreSQL database: {e}")
        if conn:
            conn.rollback()
        # Re-raise the exception to indicate a critical startup failure
        raise
    finally:
        if conn:
            conn.close()

# Call init_db during application startup
init_db()


# --- Security helper functions ---
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
    
    # Store user data in g for the request
    user_data_json = params.get('user', [None])[0]
    if user_data_json:
        g.telegram_user = json.loads(user_data_json)
    else:
        g.telegram_user = None # Or a default empty dict if you prefer
        print("Warning: Telegram init data missing 'user' object.")

    return True

# --- Admin protection middleware ---
def check_admin_credentials(username, password):
    correct_username = os.environ.get('ADMIN_USERNAME', 'admin')
    correct_password = os.environ.get('ADMIN_PASSWORD', 'securepassword')
    return username == correct_username and password == correct_password

def require_admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_admin_credentials(auth.username, auth.password):
            print(f"Admin auth failed for {request.path}") # Debug print
            return 'Could not verify your access level for that URL.\n' \
                   'You have to login with proper credentials', 401, \
                   {'WWW-Authenticate': 'Basic realm="Login Required"'}
        return f(*args, **kwargs)
    return decorated

# --- Middleware for Telegram Authentication ---
@app.before_request
def check_telegram_authentication():
    # Define a list of URL path prefixes that should be exempt from Telegram authentication.
    exempt_prefixes = ['/admin', '/analytics', '/static']
    
    # Explicitly exempt the root path '/' and favicon.ico
    if request.path == '/' or request.path == '/favicon.ico':
        return None 
    
    for prefix in exempt_prefixes:
        if request.path.startswith(prefix):
            return None # Allow the request to proceed to the next handler/route

    # If not exempt, proceed with Telegram authentication
    telegram_init_data = request.headers.get('X-Telegram-Init-Data')
    
    if not telegram_init_data:
        print(f"Missing X-Telegram-Init-Data for non-exempt route: {request.path}")
        return jsonify({'error': 'Unauthorized: Missing X-Telegram-Init-Data header'}), 401

    if not validate_telegram_data(telegram_init_data):
        return jsonify({'error': 'Unauthorized: Invalid Telegram data'}), 401
    
    pass # Let the request proceed


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_user_info', methods=['POST'])
def get_user_info():
    # We expect g.telegram_user to be set by the before_request middleware
    if not hasattr(g, 'telegram_user') or not g.telegram_user:
        return jsonify({'error': 'Telegram user data not found in request context.'}), 400

    user_data = g.telegram_user # Get user data from g object
    now = datetime.now()
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
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
            last_seen = %s,
            interactions = users.interactions + 1
        ''', (
            user_data['id'],
            user_data.get('first_name'),
            user_data.get('last_name'),
            user_data.get('username'),
            user_data.get('language_code'),
            user_data.get('is_premium', False),
            now,
            now,
            now # last_seen for update
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
            conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

# --- Admin Panel Routes ---

@app.route('/admin') # <--- This is the URL that will display admin.html
@require_admin_auth
def admin_panel():
    return render_template('admin.html')

# --- Analytics Endpoints ---

@app.route('/analytics/users/count')
@require_admin_auth
def user_count():
    conn = None
    try:
        conn = get_db_connection()
        # Use RealDictCursor for cleaner dictionary output
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) 
        cur.execute('SELECT COUNT(*) AS total_users FROM users')
        total_users_data = cur.fetchone()
        total = total_users_data['total_users'] if total_users_data else 0

        cur.execute('''
            SELECT COUNT(*) AS active_today FROM users 
            WHERE DATE(last_seen) = CURRENT_DATE
        ''')
        active_today_data = cur.fetchone()
        today = active_today_data['active_today'] if active_today_data else 0

        return jsonify({'total_users': total, 'active_today': today})
    except Exception as e:
        print(f"Error in user_count: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/analytics/users/growth')
@require_admin_auth
def user_growth():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('''
            SELECT CAST(created_at AS DATE) as date, COUNT(*) as new_users
            FROM users
            GROUP BY CAST(created_at AS DATE)
            ORDER BY date DESC
            LIMIT 30
        ''')
        growth = cur.fetchall()
        return jsonify([dict(row) for row in growth])
    except Exception as e:
        print(f"Error in user_growth: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/analytics/events/top')
@require_admin_auth
def top_events():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
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

@app.route('/admin/users')
@require_admin_auth
def admin_users():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        search_query = request.args.get('query', '').strip()
        sort_by = request.args.get('sort', 'recent') # 'recent', 'oldest', 'most_interactions'

        sql_query = "SELECT * FROM users"
        params = []
        
        if search_query:
            sql_query += " WHERE user_id::text ILIKE %s OR username ILIKE %s"
            params.append(f"%{search_query}%")
            params.append(f"%{search_query}%")

        if sort_by == 'recent':
            sql_query += " ORDER BY last_seen DESC"
        elif sort_by == 'oldest':
            sql_query += " ORDER BY created_at ASC"
        elif sort_by == 'most_interactions':
            sql_query += " ORDER BY interactions DESC"
        else: # Default to recent if invalid sort_by
            sql_query += " ORDER BY last_seen DESC"

        sql_query += " LIMIT 100" # Still limit for performance on the main page

        cur.execute(sql_query, params)
        users = cur.fetchall()
        
        return jsonify([dict(user) for user in users])
    except Exception as e:
        print(f"Error fetching admin users: {e}")
        return jsonify({'error': 'Failed to retrieve user data: ' + str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/user/<int:user_id>')
@require_admin_auth
def get_user_profile(user_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
        user = cur.fetchone()
        if user:
            return jsonify(dict(user))
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        print(f"Error fetching user profile for {user_id}: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/user/<int:user_id>/sessions')
@require_admin_auth
def get_user_sessions(user_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM user_sessions WHERE user_id = %s ORDER BY created_at DESC LIMIT 10', (user_id,))
        sessions = cur.fetchall()
        return jsonify([dict(session) for session in sessions])
    except Exception as e:
        print(f"Error fetching user sessions for {user_id}: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/user/<int:user_id>/events')
@require_admin_auth
def get_user_events(user_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM user_events WHERE user_id = %s ORDER BY created_at DESC LIMIT 20', (user_id,))
        events = cur.fetchall()
        return jsonify([dict(event) for event in events])
    except Exception as e:
        print(f"Error fetching user events for {user_id}: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/user/<int:user_id>', methods=['DELETE'])
@require_admin_auth
def delete_user_data(user_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Deleting from user_events and user_sessions first due to foreign key constraints
        # (Though with ON DELETE CASCADE, deleting from users would cascade, explicit is fine)
        cur.execute('DELETE FROM user_events WHERE user_id = %s', (user_id,))
        cur.execute('DELETE FROM user_sessions WHERE user_id = %s', (user_id,))
        cur.execute('DELETE FROM users WHERE user_id = %s', (user_id,))
        conn.commit()
        
        if cur.rowcount > 0:
            return jsonify({'message': f'User {user_id} and associated data deleted successfully.'}), 200
        return jsonify({'message': 'User not found or no data to delete.'}), 404
    except Exception as e:
        print(f"Error deleting user {user_id}: {e}")
        if conn:
            conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
