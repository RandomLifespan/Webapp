from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, g, session
import os
import psycopg2
from psycopg2 import extras # Needed for RealDictCursor
from datetime import datetime, timedelta
import hashlib
import hmac
import secrets
import urllib.parse
import json
from flask_wtf.csrf import CSRFProtect, generate_csrf # Import CSRFProtect and generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash # Import for password hashing
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production' 
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' 
app.config['TELEGRAM_BOT_TOKEN'] = os.environ.get('TELEGRAM_BOT_TOKEN', '')
app.config['SESSION_COOKIE_NAME'] = 'admin_session' 
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7) 

# Enable CSRF protection for forms. This makes csrf_token() available in templates.
# app.config['WTF_CSRF_ENABLED'] = True # Explicitly enable CSRF


app.config['WTF_CSRF_CHECK_DEFAULT'] = False

csrf = CSRFProtect(app) # Initialize CSRFProtect
csrf._exempt_views.add('api.use_service')

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

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
        app.logger.error(f"Error connecting to PostgreSQL database: {e}")
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
        cur.execute('''
        CREATE TABLE IF NOT EXISTS user_api_keys (
            id SERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            api_key TEXT NOT NULL UNIQUE,
            api_secret TEXT NOT NULL, 
            CIDR[],  
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            last_used_at TIMESTAMP WITHOUT TIME ZONE,
            expires_at TIMESTAMP WITHOUT TIME ZONE,
            is_active BOOLEAN DEFAULT TRUE,
            rate_limit INTEGER DEFAULT 10, 
            usage_count INTEGER DEFAULT 0
        );
        ''')
        cur.execute('''
        CREATE TABLE IF NOT EXISTS api_key_usage (
            id SERIAL PRIMARY KEY,
            api_key_id INTEGER REFERENCES user_api_keys(id),
            ip_address INET,
            user_agent TEXT,
            endpoint TEXT,
            status_code INTEGER,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        );
        ''')
        conn.commit()
        print("PostgreSQL tables checked/created successfully.")
    except Exception as e:
        app.logger.error(f"Error initializing PostgreSQL database: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

# Call init_db during application startup
init_db()


# --- Security helper functions ---
def validate_telegram_data(init_data_raw):
    if not app.config['TELEGRAM_BOT_TOKEN']:
        app.logger.warning("TELEGRAM_BOT_TOKEN is not set in app.config!")
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
        app.logger.warning("Hash value not found in init_data.")
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
        app.logger.warning(f"Validation failed: Calculated hash {calculated_hash} != Provided hash {hash_value}")
        return False

    auth_date_str = params.get('auth_date', [None])[0]
    if auth_date_str:
        try:
            auth_date = datetime.fromtimestamp(int(auth_date_str))
            if datetime.now() - auth_date > timedelta(seconds=3600):
                app.logger.warning("Telegram init_data is too old.")
                return False
        except ValueError:
            app.logger.warning("Invalid auth_date format.")
            return False

    # Store user data in g for the request
    user_data_json = params.get('user', [None])[0]
    if user_data_json:
        try:
            g.telegram_user = json.loads(user_data_json)
        except json.JSONDecodeError:
            app.logger.error("Invalid JSON format for Telegram user data.")
            g.telegram_user = None
            return False
    else:
        g.telegram_user = None # Or a default empty dict if you prefer
        app.logger.warning("Warning: Telegram init data missing 'user' object.")

    return True

# --- Admin protection middleware ---
def check_admin_credentials(username, password):
    correct_username = os.environ.get('ADMIN_USERNAME', 'admin')
    stored_password_hash = os.environ.get('ADMIN_PASSWORD_HASH')
    if not stored_password_hash:
        app.logger.error("ADMIN_PASSWORD_HASH environment variable is not set!")
        return False 
    return username == correct_username and check_password_hash(stored_password_hash, password)

# --- Api key middleware

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get client information
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        endpoint = request.path
        
        # Verify API key exists
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            log_api_attempt(None, client_ip, user_agent, endpoint, 401)
            return jsonify({'error': 'API key required'}), 401

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Get API key details with FOR UPDATE lock
            cur.execute('''
                SELECT * FROM user_api_keys 
                WHERE api_key = %s AND is_active = TRUE 
                AND (expires_at IS NULL OR expires_at > NOW())
                FOR UPDATE
            ''', (api_key,))
            
            api_key_data = cur.fetchone()
            
            if not api_key_data:
                log_api_attempt(None, client_ip, user_agent, endpoint, 401)
                return jsonify({'error': 'Invalid or expired API key'}), 401
                
            # Check rate limiting
            if api_key_data['usage_count'] >= api_key_data['rate_limit']:
                log_api_attempt(api_key_data['id'], client_ip, user_agent, endpoint, 429)
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'limit': api_key_data['rate_limit'],
                    'reset_in': '1 minute'
                }), 429
                
            # IP whitelist check
            if api_key_data['allowed_ips']:
                ip_allowed = False
                for allowed_ip in api_key_data['allowed_ips']:
                    if ipaddress.ip_address(client_ip) in ipaddress.ip_network(allowed_ip):
                        ip_allowed = True
                        break
                if not ip_allowed:
                    log_api_attempt(api_key_data['id'], client_ip, user_agent, endpoint, 403)
                    return jsonify({'error': 'IP not authorized'}), 403
                    
            # Request signing verification
            if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                received_signature = request.headers.get('X-API-Signature')
                timestamp = request.headers.get('X-API-Timestamp')
                
                if not received_signature or not timestamp:
                    log_api_attempt(api_key_data['id'], client_ip, user_agent, endpoint, 401)
                    return jsonify({'error': 'Signature and timestamp required'}), 401
                    
                # Verify timestamp is recent (prevent replay attacks)
                if (datetime.now() - datetime.fromtimestamp(int(timestamp))) > timedelta(minutes=5):
                    log_api_attempt(api_key_data['id'], client_ip, user_agent, endpoint, 401)
                    return jsonify({'error': 'Expired timestamp'}), 401
                    
                # Verify signature
                payload = request.get_data()
                expected_signature = hmac.new(
                    api_key_data['api_secret'].encode(),
                    f"{timestamp}:{payload.decode()}".encode(),
                    hashlib.sha256
                ).hexdigest()
                
                if not hmac.compare_digest(expected_signature, received_signature):
                    log_api_attempt(api_key_data['id'], client_ip, user_agent, endpoint, 401)
                    return jsonify({'error': 'Invalid signature'}), 401
                    
            # Update usage stats
            cur.execute('''
                UPDATE user_api_keys 
                SET 
                    last_used_at = NOW(),
                    usage_count = usage_count + 1
                WHERE id = %s
            ''', (api_key_data['id'],))
            
            # Reset counter if last update was >1 minute ago
            cur.execute('''
                UPDATE user_api_keys 
                SET usage_count = 1
                WHERE id = %s AND last_used_at < NOW() - INTERVAL '1 minute'
            ''', (api_key_data['id'],))
            
            # Store user_id and key info in g for the request
            g.api_user_id = api_key_data['user_id']
            g.api_key_info = api_key_data
            
            conn.commit()
            
            # Proceed with the request
            response = f(*args, **kwargs)
            
            # Log successful request
            log_api_attempt(api_key_data['id'], client_ip, user_agent, endpoint, response.status_code)
            
            return response
            
        except Exception as e:
            app.logger.error(f"API key verification error: {str(e)}")
            if conn:
                conn.rollback()
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            if conn:
                conn.close()
    return decorated

def log_api_attempt(api_key_id, ip, user_agent, endpoint, status_code):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO api_key_usage 
            (api_key_id, ip_address, user_agent, endpoint, status_code)
            VALUES (%s, %s, %s, %s, %s)
        ''', (api_key_id, ip, user_agent, endpoint, status_code))
        conn.commit()
    except Exception as e:
        app.logger.error(f"Error logging API attempt: {str(e)}")
    finally:
        if conn:
            conn.close()

# Modified require_admin_auth to use session
def require_admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_logged_in' in session and session['admin_logged_in']:
            # User is logged in via session, proceed with the request
            return f(*args, **kwargs)
        else:
            # Not logged in, redirect to the login page
            app.logger.info(f"Admin auth failed for {request.path}. Redirecting to login.")
            return redirect(url_for('admin_login'))
    return decorated

# --- Middleware for Telegram Authentication ---
@app.before_request
def check_telegram_authentication():

    exempt_prefixes = ['/admin', '/analytics', '/static' , '/api'] # Added logout
    if request.path == '/login.html':
        return redirect(url_for('admin_login'))
    if request.path == '/' or request.path == '/favicon.ico':
        return None
    for prefix in exempt_prefixes:
        if request.path.startswith(prefix):
            return None # Allow the request to proceed to the next handler/route

    # If not exempt, proceed with Telegram authentication
    telegram_init_data = request.headers.get('X-Telegram-Init-Data')

    if not telegram_init_data:
        app.logger.warning(f"Missing X-Telegram-Init-Data for non-exempt route: {request.path}")
        return jsonify({'error': 'Unauthorized: Missing X-Telegram-Init-Data header'}), 401

    if not validate_telegram_data(telegram_init_data):
        return jsonify({'error': 'Unauthorized: Invalid Telegram data'}), 401

    pass # Let the request proceed


# --- Routes ---

@app.route('/')
def index():
    csrf_token = generate_csrf()
    return render_template('index.html', csrf_token=csrf_token)

# NEW: Admin Login Route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request: JSON data expected'}), 400
            
        username = data.get('username')
        password = data.get('password')

        if check_admin_credentials(username, password):
            session['admin_logged_in'] = True
            session.permanent = True # Make the session permanent if you set PERMANENT_SESSION_LIFETIME
            session['admin_username'] = username # Store username in session for display
            app.logger.info(f"Admin user '{username}' logged in successfully.")
            return jsonify({'message': 'Login successful'}), 200
        else:
            app.logger.warning(f"Failed login attempt for username: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
    else:
        # If already logged in, redirect to admin dashboard
        if 'admin_logged_in' in session and session['admin_logged_in']:
            return redirect(url_for('admin_panel'))
        # Flask-WTF will automatically provide csrf_token() to the template
        return render_template('login.html')

# NEW: Admin Logout Route
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None) # Remove username from session
    app.logger.info("Admin user logged out.")
    response = redirect(url_for('admin_login'))
    return response


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
        app.logger.error(f"Error generating points for user {user_id}: {e}")
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
        app.logger.error(f"Error fetching points for user {user_id}: {e}")
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
        app.logger.error(f"Error in get_user_info: {e}")
        if conn:
            conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()
@app.route('/generate_api_key', methods=['POST'])
def generate_api_key():
    if not hasattr(g, 'telegram_user') or not g.telegram_user:
        return jsonify({'error': 'Unauthorized: Telegram user data not found.'}), 401

    user_id = g.telegram_user['id']
    now = datetime.now()
    
    # Generate random key and secret
    api_key = secrets.token_urlsafe(32)
    api_secret = secrets.token_urlsafe(64)  # For request signing
    
    # Default to 30-day expiration
    expires_at = now + timedelta(days=30)
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # First deactivate any existing keys
        cur.execute('''
            UPDATE user_api_keys 
            SET is_active = FALSE 
            WHERE user_id = %s AND is_active = TRUE
        ''', (user_id,))
        
        # Insert the new key with enhanced security
        cur.execute('''
            INSERT INTO user_api_keys 
            (user_id, api_key, api_secret, created_at, expires_at)
            VALUES (%s, %s, %s, %s, %s)
        ''', (user_id, api_key, api_secret, now, expires_at))
        
        # Log the event
        cur.execute('''
            INSERT INTO user_events (user_id, event_type, event_data, created_at)
            VALUES (%s, %s, %s, %s)
        ''', (user_id, 'api_key_generated', json.dumps({
            'action': 'generate',
            'expires_at': expires_at.isoformat()
        }), now))
        
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'api_key': api_key,
            'api_secret': api_secret,  # Only returned once!
            'expires_at': expires_at.isoformat(),
            'message': 'New API key generated. Previous keys deactivated.'
        })
        
    except Exception as e:
        app.logger.error(f"Error generating API key for user {user_id}: {e}")
        if conn:
            conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()
            

@app.route('/get_api_key', methods=['GET'])
def get_api_key():
    if not hasattr(g, 'telegram_user') or not g.telegram_user:
        return jsonify({'error': 'Unauthorized: Telegram user data not found.'}), 401

    user_id = g.telegram_user['id']
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute('''
            SELECT api_key, created_at 
            FROM user_api_keys 
            WHERE user_id = %s AND is_active = TRUE
            ORDER BY created_at DESC 
            LIMIT 1
        ''', (user_id,))
        
        api_key_data = cur.fetchone()
        
        if api_key_data:
            return jsonify({
                'status': 'success',
                'has_api_key': True,
                'api_key': api_key_data['api_key'],
                'created_at': api_key_data['created_at'].isoformat()
            })
        else:
            return jsonify({
                'status': 'success',
                'has_api_key': False,
                'message': 'No active API key found'
            })
            
    except Exception as e:
        app.logger.error(f"Error fetching API key for user {user_id}: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()
            
@app.route('/api/use_service', methods=['POST'])
@limiter.limit("10 per minute")
@api_key_required
def use_service():
    user_id = g.api_user_id
    points_to_deduct = 10  # Points to deduct per request
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Check user's current points
        cur.execute('SELECT points FROM user_points WHERE user_id = %s FOR UPDATE', (user_id,))
        user_points = cur.fetchone()
        
        if not user_points:
            return jsonify({
                'status': 'error',
                'code': 'no_points_record',
                'message': 'User points record not found'
            }), 404
            
        current_points = user_points[0]
        
        # 2. Verify sufficient points
        if current_points < points_to_deduct:
            return jsonify({
                'status': 'error',
                'code': 'insufficient_points',
                'message': f'You need at least {points_to_deduct} points to use this service',
                'required_points': points_to_deduct,
                'current_points': current_points
            }), 402  # 402 Payment Required
        
        # 3. Deduct points
        new_points = current_points - points_to_deduct
        cur.execute('''
            UPDATE user_points 
            SET points = %s 
            WHERE user_id = %s
        ''', (new_points, user_id))
        
        # 4. Log the transaction
        cur.execute('''
            INSERT INTO user_events (user_id, event_type, event_data, created_at)
            VALUES (%s, %s, %s, NOW())
        ''', (user_id, 'points_deducted', json.dumps({
            'service': 'api_use_service',
            'points_deducted': points_to_deduct,
            'remaining_points': new_points,
            'endpoint': '/api/use_service'
        })))
        
        conn.commit()
        
        # 5. Return success response
        return jsonify({
            'status': 'success',
            'message': f'Successfully used service. {points_to_deduct} points deducted.',
            'points_deducted': points_to_deduct,
            'remaining_points': new_points,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        app.logger.error(f"Error in use_service for user {user_id}: {str(e)}")
        if conn:
            conn.rollback()
        return jsonify({
            'status': 'error',
            'code': 'server_error',
            'message': 'Internal server error'
        }), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/use_service', methods=['POST'])
@limiter.limit("100 per day;10 per minute")  # Global rate limit
@api_key_required
def use_service():
    user_id = g.api_user_id
    points_to_deduct = 10
    
    # Check for suspicious activity
    if detect_suspicious_activity(g.api_key_info['id']):
        return jsonify({
            'error': 'Suspicious activity detected',
            'message': 'Your account has been temporarily restricted'
        }), 403
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check points with row locking
        cur.execute('''
            SELECT points FROM user_points 
            WHERE user_id = %s FOR UPDATE
        ''', (user_id,))
        user_points = cur.fetchone()
        
        if not user_points:
            return jsonify({
                'status': 'error',
                'code': 'no_points_record',
                'message': 'User points record not found'
            }), 404
            
        current_points = user_points[0]
        
        if current_points < points_to_deduct:
            return jsonify({
                'status': 'error',
                'code': 'insufficient_points',
                'message': f'Need {points_to_deduct} points',
                'required': points_to_deduct,
                'available': current_points
            }), 402
        
        # Deduct points
        new_points = current_points - points_to_deduct
        cur.execute('''
            UPDATE user_points 
            SET points = %s 
            WHERE user_id = %s
        ''', (new_points, user_id))
        
        # Log transaction
        cur.execute('''
            INSERT INTO user_events (user_id, event_type, event_data, created_at)
            VALUES (%s, %s, %s, NOW())
        ''', (user_id, 'points_deducted', json.dumps({
            'service': 'api_use_service',
            'points_deducted': points_to_deduct,
            'remaining_points': new_points,
            'client_ip': request.remote_addr
        })))
        
        conn.commit()
        
        return jsonify({
            'status': 'success',
            'points_deducted': points_to_deduct,
            'remaining_points': new_points,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        app.logger.error(f"Error in use_service: {str(e)}")
        if conn:
            conn.rollback()
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        if conn:
            conn.close()

def detect_suspicious_activity(api_key_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Check for multiple IPs in short time
        cur.execute('''
            SELECT COUNT(DISTINCT ip_address) as ip_count 
            FROM api_key_usage 
            WHERE api_key_id = %s 
            AND created_at > NOW() - INTERVAL '1 hour'
        ''', (api_key_id,))
        ip_count = cur.fetchone()['ip_count']
        
        # Check for failed attempts
        cur.execute('''
            SELECT COUNT(*) as fail_count 
            FROM api_key_usage 
            WHERE api_key_id = %s 
            AND status_code >= 400 
            AND created_at > NOW() - INTERVAL '10 minutes'
        ''', (api_key_id,))
        fail_count = cur.fetchone()['fail_count']
        
        return ip_count > 3 or fail_count > 5
        
    except Exception as e:
        app.logger.error(f"Error detecting suspicious activity: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()

@app.route('/admin/api_keys', methods=['GET'])
@require_admin_auth
def list_api_keys():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute('''
            SELECT k.*, u.username, u.first_name 
            FROM user_api_keys k
            LEFT JOIN users u ON k.user_id = u.user_id
            ORDER BY k.created_at DESC
            LIMIT 100
        ''')
        
        keys = []
        for row in cur.fetchall():
            key = dict(row)
            key['created_at'] = key['created_at'].isoformat() if key['created_at'] else None
            key['last_used_at'] = key['last_used_at'].isoformat() if key['last_used_at'] else None
            key['expires_at'] = key['expires_at'].isoformat() if key['expires_at'] else None
            keys.append(key)
            
        return jsonify(keys)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/api_key/<int:key_id>', methods=['DELETE'])
@require_admin_auth
def revoke_api_key(key_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute('''
            UPDATE user_api_keys 
            SET is_active = FALSE 
            WHERE id = %s
        ''', (key_id,))
        
        conn.commit()
        
        return jsonify({'message': 'API key revoked'})
        
    except Exception as e:
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
    # You might want to pass the admin username to the template here if you wish to display it
    # return render_template('admin.html', admin_username=session.get('admin_username', 'Admin'))
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
        app.logger.error(f"Error in user_count: {e}")
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
        # Serialize datetime objects
        serialized_growth = []
        for row in growth:
            row_dict = dict(row)
            if row_dict.get('date'):
                row_dict['date'] = row_dict['date'].isoformat()
            serialized_growth.append(row_dict)
        return jsonify(serialized_growth)
    except Exception as e:
        app.logger.error(f"Error in user_growth: {e}")
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
        # No datetime objects here, so direct jsonify is fine
        return jsonify([dict(row) for row in events])
    except Exception as e:
        app.logger.error(f"Error in top_events: {e}")
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
            # Ensure user_id is cast to text for ILIKE comparison
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

        # Convert datetime objects to ISO 8601 strings
        serialized_users = []
        for user in users:
            user_dict = dict(user) # Convert RealDictRow to dict
            if user_dict.get('created_at'):
                user_dict['created_at'] = user_dict['created_at'].isoformat()
            if user_dict.get('last_seen'):
                user_dict['last_seen'] = user_dict['last_seen'].isoformat()
            serialized_users.append(user_dict)

        return jsonify(serialized_users)

    except Exception as e:
        app.logger.error(f"Error fetching admin users: {e}")
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
            user_dict = dict(user)
            if user_dict.get('created_at'):
                user_dict['created_at'] = user_dict['created_at'].isoformat()
            if user_dict.get('last_seen'):
                user_dict['last_seen'] = user_dict['last_seen'].isoformat()
            return jsonify(user_dict)
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        app.logger.error(f"Error fetching user profile for {user_id}: {e}")
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

        # Serialize datetime objects for sessions
        serialized_sessions = []
        for session_data in sessions:
            session_dict = dict(session_data)
            if session_dict.get('created_at'):
                session_dict['created_at'] = session_dict['created_at'].isoformat()
            if session_dict.get('last_activity'):
                session_dict['last_activity'] = session_dict['last_activity'].isoformat()
            serialized_sessions.append(session_dict)

        return jsonify(serialized_sessions)
    except Exception as e:
        app.logger.error(f"Error fetching user sessions for {user_id}: {e}")
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

        # Serialize datetime objects for events
        serialized_events = []
        for event_data in events:
            event_dict = dict(event_data)
            if event_dict.get('created_at'):
                event_dict['created_at'] = event_dict['created_at'].isoformat()
            # event_data (JSONB) should already be a Python dict/list, so no special serialization needed unless it contains datetimes
            serialized_events.append(event_dict)

        return jsonify(serialized_events)
    except Exception as e:
        app.logger.error(f"Error fetching user events for {user_id}: {e}")
        return jsonify({'error': 'An internal server error occurred.'}), 500
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
            app.logger.info(f"User {user_id} and associated data deleted successfully by admin.")
            return jsonify({'message': f'User {user_id} and associated data deleted successfully.'}), 200
        app.logger.warning(f"Attempted to delete non-existent user {user_id}.")
        return jsonify({'message': 'User not found or no data to delete.'}), 404
    except Exception as e:
        app.logger.error(f"Error deleting user {user_id}: {e}")
        if conn:
            conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()
            
@app.errorhandler(400)
def bad_request_error(error):
    app.logger.warning(f"Bad Request: {request.url} - {error}")
    return jsonify({'error': 'Bad Request', 'message': 'The server cannot process the request due to a client error.'}), 400

@app.errorhandler(401)
def unauthorized_error(error):
    app.logger.warning(f"Unauthorized Access: {request.url} - {error}")
    return jsonify({'error': 'Unauthorized', 'message': 'Authentication is required and has failed or has not yet been provided.'}), 401

@app.errorhandler(404)
def not_found_error(error):
    app.logger.warning(f"Not Found: {request.url} - {error}")
    return jsonify({'error': 'Not Found', 'message': 'The requested URL was not found on the server.'}), 404

@app.errorhandler(405)
def method_not_allowed_error(error):
    app.logger.warning(f"Method Not Allowed: {request.method} {request.url} - {error}")
    return jsonify({'error': 'Method Not Allowed', 'message': 'The method is not allowed for the requested URL.'}), 405

@app.errorhandler(500)
def internal_server_error(error):
    app.logger.exception(f"Internal Server Error: {request.url}") # Logs the full traceback
    return jsonify({'error': 'Internal Server Error', 'message': 'Something went wrong on the server.'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
