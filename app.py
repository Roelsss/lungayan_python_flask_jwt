import datetime
import jwt
from flask import Flask, request, jsonify

# Flask app initialization
app = Flask(__name__)

# Secret key for encoding/decoding JWT tokens
SECRET_KEY = 'your_secret_key'  # You should change this in production!

# In-memory mock database for users
users_db = {}


# Helper function to create a JWT token
def create_jwt(user_id):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    payload = {
        'sub': user_id,  # Subject claim (usually user ID)
        'exp': expiration
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


# POST /register: Register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Username and password are required"}), 400

    username = data['username']
    password = data['password']

    if username in users_db:
        return jsonify({"message": "User already exists"}), 400

    users_db[username] = password  # Simulate saving user to database

    return jsonify({"message": f"User {username} registered successfully!"}), 201


# POST /login: Authenticate user and issue JWT
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Username and password are required"}), 400

    username = data['username']
    password = data['password']

    if username not in users_db or users_db[username] != password:
        return jsonify({"message": "Invalid username or password"}), 401

    # User is authenticated, create a JWT token
    token = create_jwt(username)

    return jsonify({"token": token}), 200


# GET /get-jwt: Get the current user's JWT token (requires authentication)
@app.route('/get-jwt', methods=['GET'])
def get_jwt():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"message": "Token is missing!"}), 401

    try:
        token = token.split(' ')[1]  # Extract token from 'Bearer <token>'
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired!"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token!"}), 401

    return jsonify({"message": "Token is valid!", "user": payload['sub']}), 200


# POST /set-jwt: Set a JWT token (for testing purposes)
@app.route('/set-jwt', methods=['POST'])
def set_jwt():
    data = request.get_json()

    if 'user_id' not in data:
        return jsonify({"message": "User ID is required"}), 400

    user_id = data['user_id']
    token = create_jwt(user_id)

    return jsonify({"token": token}), 200


# Start Flask server
if __name__ == '__main__':
    app.run(debug=True)