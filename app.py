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
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity, exceptions as jwt_exceptions
from flask_cors import CORS 


app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32)) # Renamed to avoid confusion with JWT_SECRET_KEY
app.config['TELEGRAM_BOT_TOKEN'] = os.environ.get('TELEGRAM_BOT_TOKEN', '')

# --- JWT Configuration ---
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32)) # Set a strong, unique key
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1) # Token valid for 1 hour
jwt = JWTManager(app)
# --- End JWT Configuration ---

CORS(app, resources={r"/https://web-production-022e9.up.railway.app": {"origins": "*"}}, 
     supports_credentials=True, 
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], # Explicitly allow OPTIONS for preflight
     headers=["Content-Type", "Authorization"]) # CRITICAL: Allow the Authorization header


# --- End CORS Configuration ---
# --- JWT Error Handlers (important for clean 401s for admin panel) ---
@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({"msg": "Missing Authorization Header or Token"}), 401

@jwt.invalid_token_loader
def invalid_token_response(callback):
    return jsonify({"msg": "Signature verification failed"}), 401

@jwt.expired_token_loader
def expired_token_response(callback):
    return jsonify({"msg": "Token has expired"}), 401

@jwt.revoked_token_loader
def revoked_token_response(callback):
    return jsonify({"msg": "Token has been revoked"}), 401
# --- End JWT Error Handlers ---


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

        # NEW TABLE FOR POINTS
        cur.execute('''
        CREATE TABLE IF NOT EXISTS user_points (
            user_id BIGINT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
            points INTEGER DEFAULT 0,
            last_generated_at TIMESTAMP WITHOUT TIME ZONE
        );
        ''')

        conn.commit()
        print("PostgreSQL tables checked/created successfully.")
    except Exception as e:
        print(f"Error initializing PostgreSQL database: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

# Call init_db during application startup
with app.app_context(): # Run init_db within app context
    init_db()


# --- Security helper functions for Telegram ---
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
            # Data should not be older than 1 hour (3600 seconds)
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

# --- Admin Authentication (JWT-based) ---
def get_admin_credentials():
    """Retrieve admin username and password from environment variables."""
    return {
        "username": os.environ.get('ADMIN_USERNAME', 'admin'),
        "password": os.environ.get('ADMIN_PASSWORD', 'securepassword') # NEVER use default 'securepassword' in production
    }

def require_admin_auth(f):
    """Decorator to protect admin routes with JWT and check for admin role."""
    @wraps(f)
    @jwt_required() # Require a valid JWT token
    def decorated_function(*args, **kwargs):
        current_user_identity = get_jwt_identity() # Get the identity from the JWT (which is the username)
        admin_creds = get_admin_credentials()

        # Simple check: Is the logged-in user the configured admin username?
        # In a real app, you'd have a 'roles' field in your DB and check that.
        if current_user_identity != admin_creds["username"]:
            return jsonify({"msg": "Admin access required"}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# --- Middleware for Telegram Authentication (unchanged) ---
@app.before_request
def check_telegram_authentication():
    # Define a list of URL path prefixes that should be exempt from Telegram authentication.
    # Now includes /admin_login and /login.html
    exempt_prefixes = ['/admin', '/analytics', '/static', '/login', '/login.html']
    
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
    
@app.route('/generate_points', methods=['POST'])
def generate_points():
    if not hasattr(g, 'telegram_user') or not g.telegram_user:
        return jsonify({'error': 'Unauthorized: Telegram user data not found.'}), 401

    user_id = g.telegram_user['id']
    now = datetime.now()
    cooldown_duration = timedelta(minutes=5) # 5 minutes cooldown

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch current points and last generated time
        cur.execute("SELECT points, last_generated_at FROM user_points WHERE user_id = %s", (user_id,))
        user_points_data = cur.fetchone()

        current_points = 0
        last_generated_at = None

        if user_points_data:
            current_points = user_points_data[0]
            last_generated_at = user_points_data[1]

        # Check for cooldown
        if last_generated_at and (now - last_generated_at) < cooldown_duration:
            time_left = (cooldown_duration - (now - last_generated_at)).total_seconds()
            return jsonify({
                'status': 'cooldown',
                'message': f'You need to wait {int(time_left // 60)} minutes and {int(time_left % 60)} seconds before generating points again.',
                'cooldown_seconds_left': int(time_left)
            }), 429 # Too Many Requests

        # Generate points (e.g., add 10 points)
        points_to_add = 10
        new_points = current_points + points_to_add

        # Update or insert user points and last generated timestamp
        cur.execute('''
            INSERT INTO user_points (user_id, points, last_generated_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE SET
                points = EXCLUDED.points,
                last_generated_at = EXCLUDED.last_generated_at
        ''', (user_id, new_points, now))

        # Log the event
        cur.execute('''
            INSERT INTO user_events (user_id, event_type, event_data, created_at)
            VALUES (%s, %s, %s, %s)
        ''', (user_id, 'points_generated', json.dumps({'points_added': points_to_add, 'new_total': new_points}), now))

        conn.commit()

        return jsonify({
            'status': 'success',
            'message': f'Successfully generated {points_to_add} points!',
            'new_total_points': new_points
        })

    except Exception as e:
        print(f"Error generating points for user {user_id}: {e}")
        if conn:
            conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/get_user_points', methods=['GET'])
def get_user_points():
    if not hasattr(g, 'telegram_user') or not g.telegram_user:
        return jsonify({'error': 'Unauthorized: Telegram user data not found.'}), 401

    user_id = g.telegram_user['id']
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT points, last_generated_at FROM user_points WHERE user_id = %s", (user_id,))
        user_points_data = cur.fetchone()

        if user_points_data:
            return jsonify({
                'status': 'success',
                'points': user_points_data['points'],
                'last_generated_at': user_points_data['last_generated_at'].isoformat() if user_points_data['last_generated_at'] else None
            })
        else:
            return jsonify({
                'status': 'success',
                'points': 0,
                'last_generated_at': None,
                'message': 'No points found for this user.'
            })
    except Exception as e:
        print(f"Error fetching points for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()
            
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

# --- Admin Panel Login Route ---
@app.route('/login', methods=['POST'])
def admin_login():
    """Handles admin login and issues a JWT token."""
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    admin_creds = get_admin_credentials()

    if username == admin_creds["username"] and password == admin_creds["password"]:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.route('/login.html')
def login_html_page():
    return render_template('login.html')


# --- Admin Panel Routes (protected by JWT) ---

@app.route('/admin') # This is the URL that will display admin.html
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
            sql_query += " WHERE user_id::text ILIKE %s OR username ILIKE %s OR first_name ILIKE %s OR last_name ILIKE %s"
            params.append(f"%{search_query}%")
            params.append(f"%{search_query}%")
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
        
        # Deleting from user_events, user_sessions, and user_points first due to foreign key constraints
        cur.execute('DELETE FROM user_events WHERE user_id = %s', (user_id,))
        cur.execute('DELETE FROM user_sessions WHERE user_id = %s', (user_id,))
        cur.execute('DELETE FROM user_points WHERE user_id = %s', (user_id,)) # Added this line
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
