from flask import Flask, request, jsonify, render_template
import os
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Database setup
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
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
        ''')
        conn.commit()
        conn.close()

# Initialize database
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/get_user_info', methods=['POST'])
def get_user_info():
    data = request.json
    
    if not data or 'user' not in data:
        return jsonify({'error': 'Invalid data'}), 400
    
    user_data = data['user']
    now = datetime.now().isoformat()
    
    try:
        conn = get_db_connection()
        
        # Check if user exists
        existing = conn.execute(
            'SELECT * FROM users WHERE user_id = ?',
            (user_data['id'],)
        ).fetchone()
        
        if existing:
            # Update last_seen for existing user
            conn.execute(
                '''UPDATE users SET 
                first_name = ?,
                last_name = ?,
                username = ?,
                last_seen = ?
                WHERE user_id = ?''',
                (
                    user_data.get('first_name'),
                    user_data.get('last_name'),
                    user_data.get('username'),
                    now,
                    user_data['id']
                )
            )
        else:
            # Insert new user
            conn.execute(
                '''INSERT INTO users 
                (user_id, first_name, last_name, username, created_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)''',
                (
                    user_data['id'],
                    user_data.get('first_name'),
                    user_data.get('last_name'),
                    user_data.get('username'),
                    now,
                    now
                )
            )
        
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
        return jsonify({'error': str(e)}), 500

# Add a route to view all users (for debugging)
@app.route('/users')
def list_users():
    try:
        conn = get_db_connection()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.close()
        return jsonify([dict(user) for user in users])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
