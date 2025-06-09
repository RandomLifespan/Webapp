import os
import psycopg2
from psycopg2 import extras
from datetime import datetime, timedelta
import hashlib
import hmac
import secrets
import urllib.parse
import json
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['TELEGRAM_BOT_TOKEN'] = os.environ.get('TELEGRAM_BOT_TOKEN', '')

# Configure logging
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.DEBUG)
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

# Database Connection
def get_db_connection():
    try:
        db_url = os.environ.get('DATABASE_URL')
        if not db_url:
            app.logger.error("DATABASE_URL environment variable is not set")
            raise ValueError("DATABASE_URL not set")

        conn = psycopg2.connect(db_url)
        return conn
    except Exception as e:
        app.logger.error(f"Error connecting to PostgreSQL: {e}")
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
        app.logger.info("Database tables initialized successfully")
    except Exception as e:
        app.logger.error(f"Error initializing database: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

init_db()

# Security Helpers
def validate_telegram_data(init_data_raw):
    if not app.config['TELEGRAM_BOT_TOKEN']:
        app.logger.error("TELEGRAM_BOT_TOKEN not configured")
        return False

    try:
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
            app.logger.error("Hash value missing in init_data")
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
            app.logger.error(f"Hash mismatch: {calculated_hash} vs {hash_value}")
            return False
        
        auth_date_str = params.get('auth_date', [None])[0]
        if auth_date_str:
            try:
                auth_date = datetime.fromtimestamp(int(auth_date_str))
                if datetime.now() - auth_date > timedelta(seconds=3600):
                    app.logger.error("Telegram auth data expired")
                    return False
            except ValueError:
                app.logger.error("Invalid auth_date format")
                return False
        
        user_data_json = params.get('user', [None])[0]
        if user_data_json:
            try:
                g.telegram_user = json.loads(user_data_json)
                app.logger.debug(f"Telegram user data: {g.telegram_user}")
            except json.JSONDecodeError:
                app.logger.error("Invalid user JSON data")
                return False
        else:
            app.logger.error("Missing user data in init_data")
            return False

        return True

    except Exception as e:
        app.logger.error(f"Error validating Telegram data: {e}")
        return False

# Middleware
@app.before_request
def check_telegram_authentication():
    exempt_prefixes = ['/admin', '/analytics', '/static', '/']
    
    if request.path == '/favicon.ico':
        return None
        
    for prefix in exempt_prefixes:
        if request.path.startswith(prefix):
            return None

    telegram_init_data = request.headers.get('X-Telegram-Init-Data')
    
    if not telegram_init_data:
        app.logger.error(f"Missing X-Telegram-Init-Data for {request.path}")
        return jsonify({'error': 'Missing authentication data'}), 401

    if not validate_telegram_data(telegram_init_data):
        return jsonify({'error': 'Invalid authentication'}), 401

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_user_info', methods=['POST'])
def get_user_info():
    if not hasattr(g, 'telegram_user') or not g.telegram_user:
        app.logger.error("No telegram_user in request context")
        return jsonify({'error': 'User data missing'}), 400

    user_data = g.telegram_user
    if 'id' not in user_data:
        app.logger.error("User ID missing in Telegram data")
        return jsonify({'error': 'Invalid user data'}), 400

    now = datetime.now()
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Try to update existing user first
        cur.execute('''
        UPDATE users SET
            first_name = %s,
            last_name = %s,
            username = %s,
            language_code = %s,
            is_premium = %s,
            last_seen = %s,
            interactions = interactions + 1
        WHERE user_id = %s
        RETURNING id
        ''', (
            user_data.get('first_name'),
            user_data.get('last_name'),
            user_data.get('username'),
            user_data.get('language_code'),
            user_data.get('is_premium', False),
            now,
            user_data['id']
        ))
        
        updated_user = cur.fetchone()
        
        if not updated_user:
            # Insert new user if update didn't affect any rows
            app.logger.info(f"Creating new user: {user_data['id']}")
            cur.execute('''
            INSERT INTO users (
                user_id, first_name, last_name, username, 
                language_code, is_premium, created_at, last_seen
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s
            ) RETURNING id
            ''', (
                user_data['id'],
                user_data.get('first_name'),
                user_data.get('last_name'),
                user_data.get('username'),
                user_data.get('language_code'),
                user_data.get('is_premium', False),
                now,
                now
            ))
            new_user = cur.fetchone()
            app.logger.info(f"Created new user with ID: {new_user[0]}")

        # Log session
        session_id = hashlib.sha256(f"{user_data['id']}{now}{secrets.token_hex(8)}".encode()).hexdigest()
        cur.execute('''
        INSERT INTO user_sessions (
            session_id, user_id, ip_address, user_agent, 
            referrer, created_at, last_activity
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s
        )
        ''', (
            session_id,
            user_data['id'],
            request.headers.get('X-Forwarded-For', request.remote_addr),
            request.headers.get('User-Agent'),
            request.headers.get('Referer'),
            now,
            now
        ))
        
        # Log event
        cur.execute('''
        INSERT INTO user_events (
            user_id, event_type, event_data, created_at
        ) VALUES (
            %s, %s, %s, %s
        )
        ''', (
            user_data['id'],
            'mini_app_launch',
            json.dumps({
                'path': request.path,
                'method': request.method,
                'user_agent': request.headers.get('User-Agent')
            }),
            now
        ))
        
        conn.commit()
        return jsonify({
            'status': 'success',
            'user_id': user_data['id'],
            'first_name': user_data.get('first_name'),
            'username': user_data.get('username')
        })
        
    except psycopg2.IntegrityError as e:
        conn.rollback()
        app.logger.error(f"Database integrity error: {e}")
        return jsonify({'error': 'User already exists'}), 400
    except Exception as e:
        if conn:
            conn.rollback()
        app.logger.error(f"Error in get_user_info: {e}")
        return jsonify({'error': 'Internal server error'}), 500
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
