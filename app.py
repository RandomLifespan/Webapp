from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, g
import os
import psycopg2
from psycopg2 import extras
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

# --- Admin protection middleware ---
def require_admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        # For simplicity, during development, you might comment this out temporarily
        # to ensure the analytics routes themselves work without auth, then re-enable.
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

# --- PostgreSQL Database Connection ---
def get_db_connection():
    try:
        conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def init_db():
    conn = get_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT UNIQUE NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    username TEXT,
                    language_code TEXT,
                    is_premium BOOLEAN,
                    added_to_attachment_menu BOOLEAN,
                    allows_write_to_pm BOOLEAN,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    interactions INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id SERIAL PRIMARY KEY,
                    session_id UUID DEFAULT gen_random_uuid(),
                    user_id BIGINT REFERENCES users(user_id) ON DELETE CASCADE,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS events (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT REFERENCES users(user_id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    event_data JSONB,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
            print("Database initialized successfully.")
        except Exception as e:
            print(f"Error initializing database: {e}")
            conn.rollback()
        finally:
            conn.close()
    else:
        print("Could not connect to database for initialization.")

init_db()

# --- Security helper functions (remain largely the same) ---
def validate_telegram_data(init_data_raw):
    # ... (rest of the function remains the same, ensure it properly extracts user data into g.telegram_user)
    try:
        parsed_data = urllib.parse.parse_qs(init_data_raw)
        
        # Check hash
        data_check_string_parts = []
        hash_to_check = ''
        for key, value_list in sorted(parsed_data.items()):
            value = value_list[0]
            if key == 'hash':
                hash_to_check = value
            else:
                data_check_string_parts.append(f"{key}={value}")
        
        data_check_string = "\n".join(data_check_string_parts)
        
        secret_key = hmac.new("WebAppData".encode('utf-8'),
                              app.config['TELEGRAM_BOT_TOKEN'].encode('utf-8'),
                              hashlib.sha256).digest()
        
        calculated_hash = hmac.new(secret_key,
                                   data_check_string.encode('utf-8'),
                                   hashlib.sha256).hexdigest()

        if calculated_hash != hash_to_check:
            print("Telegram data validation failed: Hash mismatch.")
            return False
        
        # If hash is valid, extract user data and store in Flask's g object
        user_data_json = parsed_data.get('user', [None])[0]
        if user_data_json:
            g.telegram_user = json.loads(user_data_json)
        else:
            # For testing without a user object, you might add a dummy here
            g.telegram_user = {'id': 0, 'first_name': 'TestUser', 'is_bot': False}
            print("Warning: Telegram init data missing 'user' object.") # Log if user data is missing
            
        return True
    except Exception as e:
        print(f"Error validating Telegram data: {e}")
        return False


# --- Middleware for Telegram Authentication ---
@app.before_request
def check_telegram_authentication():
    excluded_routes = [
        '/admin', # This covers /admin and /admin/users etc.
        '/static/' # Important for CSS/JS files
    ]

    # Check if the current request path starts with any of the excluded routes
    for route_prefix in excluded_routes:
        if request.path.startswith(route_prefix):
            return None # Skip Telegram authentication for this route

    init_data_raw = request.headers.get('X-Telegram-Init-Data')
    if not init_data_raw:
        print("Missing X-Telegram-Init-Data header for non-excluded route:", request.path) # Debug log
        return jsonify({"error": "Unauthorized: Missing X-Telegram-Init-Data header"}), 401

    if not validate_telegram_data(init_data_raw):
        print("Invalid Telegram Init Data for route:", request.path) # Debug log
        return jsonify({"error": "Unauthorized: Invalid Telegram Init Data"}), 401
    
    # Optional: If you want to log user activity or ensure user exists in DB
    # This might be redundant if done in /get_user_info
    # if g.telegram_user:
    #     user_id = g.telegram_user['id']
    #     username = g.telegram_user.get('username')
    #     first_name = g.telegram_user.get('first_name')
    #     last_name = g.telegram_user.get('last_name')
    #     is_premium = g.telegram_user.get('is_premium', False)
    #     language_code = g.telegram_user.get('language_code')
    #     
    #     conn = get_db_connection()
    #     if conn:
    #         try:
    #             cur = conn.cursor()
    #             cur.execute("""
    #                 INSERT INTO users (user_id, username, first_name, last_name, is_premium, language_code, last_seen, interactions)
    #                 VALUES (%s, %s, %s, %s, %s, %s, NOW(), 1)
    #                 ON CONFLICT (user_id) DO UPDATE
    #                 SET last_seen = NOW(), interactions = users.interactions + 1,
    #                     username = EXCLUDED.username, first_name = EXCLUDED.first_name,
    #                     last_name = EXCLUDED.last_name, is_premium = EXCLUDED.is_premium,
    #                     language_code = EXCLUDED.language_code;
    #             """, (user_id, username, first_name, last_name, is_premium, language_code))
    #             conn.commit()
    #         except Exception as e:
    #             print(f"Error updating user activity in before_request: {e}")
    #             conn.rollback()
    #         finally:
    #             conn.close()

    pass # Continue to the route

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_user_info', methods=['POST'])
def get_user_info():
    # This route is typically called by the Telegram Mini App
    if not hasattr(g, 'telegram_user'):
        return jsonify({"error": "Telegram user data not available"}), 400

    user_id = g.telegram_user['id']
    username = g.telegram_user.get('username')
    first_name = g.telegram_user.get('first_name')
    last_name = g.telegram_user.get('last_name')
    is_premium = g.telegram_user.get('is_premium', False)
    language_code = g.telegram_user.get('language_code')

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (user_id, username, first_name, last_name, is_premium, language_code, last_seen, interactions)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), 1)
            ON CONFLICT (user_id) DO UPDATE
            SET last_seen = NOW(), interactions = users.interactions + 1,
                username = EXCLUDED.username, first_name = EXCLUDED.first_name,
                last_name = EXCLUDED.last_name, is_premium = EXCLUDED.is_premium,
                language_code = EXCLUDED.language_code;
        """, (user_id, username, first_name, last_name, is_premium, language_code))
        conn.commit()
        return jsonify({"message": "User info received and updated", "user_id": user_id})
    except Exception as e:
        conn.rollback()
        print(f"Error in get_user_info: {e}")
        return jsonify({"error": f"Failed to update user info: {e}"}), 500
    finally:
        conn.close()

# --- Analytics Endpoints ---
@app.route('/analytics/users/count')
@require_admin_auth # Ensure this is present
def user_count():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Total users
        cur.execute("SELECT COUNT(*) AS total_users FROM users;")
        total_users_count = cur.fetchone()['total_users']

        # Active today (users who had an interaction/last_seen today)
        today = datetime.now().date()
        cur.execute("SELECT COUNT(*) AS active_today FROM users WHERE last_seen::date = %s;", (today,))
        active_today_count = cur.fetchone()['active_today']

        return jsonify({
            "total_users": total_users_count,
            "active_today": active_today_count
        })
    except Exception as e:
        print(f"Error fetching user count analytics: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/analytics/events/top')
@require_admin_auth # Ensure this is present
def top_events():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        # Get top event types by count
        cur.execute("""
            SELECT event_type, COUNT(*) AS count
            FROM events
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 5;
        """)
        top_events_data = cur.fetchall()
        return jsonify(top_events_data)
    except Exception as e:
        print(f"Error fetching top events analytics: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

# --- Admin Panel Routes ---
@app.route('/admin')
@require_admin_auth
def admin_panel():
    return render_template('admin.html')

@app.route('/admin/users')
@require_admin_auth
def admin_users():
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        search_query = request.args.get('query', '').strip()
        sort_by = request.args.get('sort', 'recent')

        sql_query = "SELECT id, user_id, first_name, last_name, username, interactions, last_seen, created_at, is_premium, language_code FROM users"
        params = []
        
        if search_query:
            sql_query += " WHERE user_id::text ILIKE %s OR username ILIKE %s"
            params.append(f"%{search_query}%")
            params.append(f"%{search_query}%")

        if sort_by == 'oldest':
            sql_query += " ORDER BY created_at ASC"
        elif sort_by == 'most_interactions':
            sql_query += " ORDER BY interactions DESC"
        else: # 'recent' or default
            sql_query += " ORDER BY last_seen DESC"

        cur.execute(sql_query, params)
        users = cur.fetchall()
        
        # Return as JSON for the client-side rendering
        return jsonify([dict(user) for user in users])
    except Exception as e:
        print(f"Error fetching admin users: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/user/<int:user_id>')
@require_admin_auth
def get_user_profile(user_id):
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id, user_id, first_name, last_name, username, language_code, is_premium, interactions, created_at, last_seen FROM users WHERE user_id = %s;", (user_id,))
        user_data = cur.fetchone()
        if user_data:
            return jsonify(dict(user_data))
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        print(f"Error fetching user profile for {user_id}: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/user/<int:user_id>/sessions')
@require_admin_auth
def get_user_sessions(user_id):
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT session_id, ip_address, user_agent, created_at, last_activity FROM sessions WHERE user_id = %s ORDER BY last_activity DESC LIMIT 10;", (user_id,))
        sessions = cur.fetchall()
        return jsonify([dict(s) for s in sessions])
    except Exception as e:
        print(f"Error fetching sessions for {user_id}: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/user/<int:user_id>/events')
@require_admin_auth
def get_user_events(user_id):
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT event_type, event_data, created_at FROM events WHERE user_id = %s ORDER BY created_at DESC LIMIT 10;", (user_id,))
        events = cur.fetchall()
        return jsonify([dict(e) for e in events])
    except Exception as e:
        print(f"Error fetching events for {user_id}: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/admin/user/<int:user_id>', methods=['DELETE'])
@require_admin_auth
def delete_user_data(user_id):
    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        cur = conn.cursor()
        # Using CASCADE DELETE on foreign keys is crucial here
        cur.execute("DELETE FROM users WHERE user_id = %s;", (user_id,))
        conn.commit()
        if cur.rowcount > 0:
            return jsonify({"message": f"User {user_id} and associated data deleted successfully."}), 200
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        conn.rollback()
        print(f"Error deleting user {user_id}: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    init_db()
    app.run(host='0.0.0.0', port=port, debug=True)
