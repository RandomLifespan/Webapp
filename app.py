from flask import Flask, request, jsonify, render_template
import os

app = Flask(__name__)

@app.route('/')
def index():
    # This is the endpoint Telegram will open as a Mini App
    return render_template('index.html')

@app.route('/get_user_info', methods=['POST'])
def get_user_info():
    # This endpoint will receive user data from the Telegram Mini App
    data = request.json
    
    if not data or 'user' not in data:
        return jsonify({'error': 'Invalid data'}), 400
    
    user_data = data['user']
    
    # Extract user information
    user_id = user_data.get('id')
    first_name = user_data.get('first_name', '')
    last_name = user_data.get('last_name', '')
    username = user_data.get('username', '')
    
    # Here you can save the user data to a database if needed
    print(f"Received user data: ID={user_id}, Name={first_name} {last_name}, Username=@{username}")
    
    return jsonify({
        'status': 'success',
        'user_id': user_id,
        'first_name': first_name,
        'last_name': last_name,
        'username': username
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)