from flask import Flask, request, jsonify, session
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import redis
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Redis for temporary storage
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per minute"]
)

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing credentials"}), 400
    
    username = data['username']
    password = data['password']
    
    stored_user = redis_client.hgetall(f"user:{username}")
    if not stored_user or not check_password_hash(stored_user['password'], password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    session['user_id'] = username
    return jsonify({"message": "Login successful"})

@app.route('/api/save', methods=['POST'])
def save_clipboard():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "Missing text data"}), 400
    
    key = secrets.token_urlsafe(32)
    expiry = 300  # 5 minutes
    
    clipboard_data = {
        'text': data['text'],
        'user_id': session['user_id'],
        'created_at': datetime.now().isoformat()
    }
    
    redis_client.hmset(f"clipboard:{key}", clipboard_data)
    redis_client.expire(f"clipboard:{key}", expiry)
    
    return jsonify({
        "key": key,
        "expires_in": expiry
    })

@app.route('/api/get/<key>', methods=['GET'])
def get_clipboard(key):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    clipboard_data = redis_client.hgetall(f"clipboard:{key}")
    if not clipboard_data:
        return jsonify({"error": "Not found or expired"}), 404
    
    if clipboard_data['user_id'] != session['user_id']:
        return jsonify({"error": "Unauthorized"}), 403
    
    return jsonify({
        "text": clipboard_data['text'],
        "created_at": clipboard_data['created_at']
    })

if __name__ == '__main__':
    app.run(ssl_context='adhoc')