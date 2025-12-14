from flask import Flask, request, jsonify, session, make_response
from functools import wraps
import secrets
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# In-memory database
users_db = {
    1: {"id": 1, "username": "alice", "email": "alice@test.com", "password": "pass123", "role": "user", "api_key": "alice_key_12345"},
    2: {"id": 2, "username": "bob", "email": "bob@test.com", "password": "pass456", "role": "user", "api_key": "bob_key_67890"},
    3: {"id": 3, "username": "admin", "email": "admin@test.com", "password": "admin123", "role": "admin", "api_key": "admin_key_99999"}
}

organizations_db = {
    1: {"id": 1, "name": "Alice Corp", "owner_id": 1, "members": [1], "invite_token": "invite_alice_abc123"},
    2: {"id": 2, "name": "Bob Industries", "owner_id": 2, "members": [2], "invite_token": "invite_bob_xyz789"},
    3: {"id": 3, "name": "Admin Group", "owner_id": 3, "members": [3], "invite_token": "invite_admin_master"}
}

documents_db = {
    1: {"id": 1, "user_id": 1, "title": "Alice Secret Doc", "content": "Alice's private password: supersecret123"},
    2: {"id": 2, "user_id": 2, "title": "Bob Financial Report", "content": "Bob's bank account: 1234567890"},
    3: {"id": 3, "user_id": 3, "title": "Admin Credentials", "content": "Admin SSH Key: ssh-rsa AAAA..."}
}

sessions_db = {}

# Helper to get current user
def get_current_user():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    cookie_token = request.cookies.get('session_token')

    auth_token = token or cookie_token
    if auth_token and auth_token in sessions_db:
        return sessions_db[auth_token]
    return None

# Authentication decorator (intentionally weak for testing)
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return jsonify({
        "app": "IDOR Vulnerable Test API",
        "endpoints": {
            "auth": {
                "POST /api/login": "Login with username & password",
                "GET /api/logout": "Logout"
            },
            "vulnerable_endpoints": {
                "GET /api/users/<id>": "IDOR - Get any user profile",
                "PUT /api/users/<id>": "IDOR - Update any user profile",
                "GET /api/documents/<id>": "IDOR - Access any user's document",
                "GET /api/organizations/<id>": "IDOR - Access any organization",
                "PUT /api/organizations/<id>/invite": "IDOR - Copy organization invite token",
                "GET /api/organizations/<id>/members": "IDOR - View organization members",
                "POST /api/organizations/<id>/join": "IDOR - Join organization with token"
            },
            "test_credentials": {
                "user1": {"username": "alice", "password": "pass123"},
                "user2": {"username": "bob", "password": "pass456"},
                "admin": {"username": "admin", "password": "admin123"}
            }
        }
    })

# === AUTHENTICATION ENDPOINTS ===

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    for user in users_db.values():
        if user['username'] == username and user['password'] == password:
            token = secrets.token_urlsafe(32)
            sessions_db[token] = user['id']

            response = make_response(jsonify({
                "message": "Login successful",
                "user_id": user['id'],
                "token": token,
                "username": user['username']
            }))
            response.set_cookie('session_token', token, httponly=False)
            return response, 200

    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['GET'])
@login_required
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if token in sessions_db:
        del sessions_db[token]
    return jsonify({"message": "Logged out"}), 200

# === VULNERABLE ENDPOINTS - IDOR Issues ===

@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    """IDOR VULNERABILITY: No authorization check - any authenticated user can view any profile"""
    current_user_id = get_current_user()

    # VULNERABLE: Should check if current_user_id == user_id
    # But we skip this check intentionally

    if user_id not in users_db:
        return jsonify({"error": "User not found"}), 404

    user = users_db[user_id].copy()
    # Intentionally leaking sensitive data
    return jsonify({
        "id": user['id'],
        "username": user['username'],
        "email": user['email'],
        "role": user['role'],
        "api_key": user['api_key'],  # SENSITIVE DATA LEAK
        "accessed_by": current_user_id
    }), 200

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """IDOR VULNERABILITY: Can update any user's profile"""
    current_user_id = get_current_user()
    data = request.get_json() or {}

    # VULNERABLE: No check if current_user_id == user_id

    if user_id not in users_db:
        return jsonify({"error": "User not found"}), 404

    # Allow updating email and role (privilege escalation possible!)
    if 'email' in data:
        users_db[user_id]['email'] = data['email']
    if 'role' in data:
        users_db[user_id]['role'] = data['role']  # PRIVILEGE ESCALATION!

    return jsonify({
        "message": "User updated",
        "user": users_db[user_id],
        "updated_by": current_user_id
    }), 200

@app.route('/api/documents/<int:doc_id>', methods=['GET'])
@login_required
def get_document(doc_id):
    """IDOR VULNERABILITY: Access any user's private documents"""
    current_user_id = get_current_user()

    # VULNERABLE: Should check if documents_db[doc_id]['user_id'] == current_user_id

    if doc_id not in documents_db:
        return jsonify({"error": "Document not found"}), 404

    doc = documents_db[doc_id]
    return jsonify({
        "id": doc['id'],
        "title": doc['title'],
        "content": doc['content'],  # SENSITIVE DATA
        "owner_id": doc['user_id'],
        "accessed_by": current_user_id
    }), 200

@app.route('/api/organizations/<int:org_id>', methods=['GET'])
@login_required
def get_organization(org_id):
    """IDOR VULNERABILITY: View any organization details"""
    current_user_id = get_current_user()

    # VULNERABLE: Should check if current_user_id in organizations_db[org_id]['members']

    if org_id not in organizations_db:
        return jsonify({"error": "Organization not found"}), 404

    org = organizations_db[org_id]
    return jsonify({
        "id": org['id'],
        "name": org['name'],
        "owner_id": org['owner_id'],
        "members": org['members'],
        "accessed_by": current_user_id
    }), 200

@app.route('/api/organizations/<int:org_id>/invite', methods=['PUT', 'POST'])
@login_required
def copy_invite_token(org_id):
    """CRITICAL IDOR: Copy/resend organization invite token - Account Takeover!
    This is the same vulnerability as in the HackLido blog post"""
    current_user_id = get_current_user()

    # VULNERABLE: Should verify current_user_id == organizations_db[org_id]['owner_id']
    # But we don't check ownership!

    if org_id not in organizations_db:
        return jsonify({"error": "Organization not found"}), 404

    org = organizations_db[org_id]

    # ANY authenticated user can get ANY organization's invite token!
    return jsonify({
        "message": "Invite token retrieved successfully",
        "organization_id": org['id'],
        "organization_name": org['name'],
        "invite_token": org['invite_token'],  # CRITICAL DATA LEAK
        "invite_link": f"https://app.example.com/join?token={org['invite_token']}",
        "retrieved_by": current_user_id,
        "actual_owner": org['owner_id']
    }), 200

@app.route('/api/organizations/<int:org_id>/members', methods=['GET'])
@login_required
def get_org_members(org_id):
    """IDOR VULNERABILITY: View members of any organization"""
    current_user_id = get_current_user()

    if org_id not in organizations_db:
        return jsonify({"error": "Organization not found"}), 404

    org = organizations_db[org_id]
    member_details = [users_db[uid] for uid in org['members'] if uid in users_db]

    return jsonify({
        "organization_id": org['id'],
        "members": member_details,  # Full user details leaked
        "accessed_by": current_user_id
    }), 200

@app.route('/api/organizations/<int:org_id>/join', methods=['POST'])
def join_organization(org_id):
    """Use stolen invite token to join organization"""
    data = request.get_json() or {}
    invite_token = data.get('invite_token')
    user_id = data.get('user_id')

    if org_id not in organizations_db:
        return jsonify({"error": "Organization not found"}), 404

    org = organizations_db[org_id]

    if org['invite_token'] == invite_token:
        if user_id not in org['members']:
            org['members'].append(user_id)
        return jsonify({
            "message": "Successfully joined organization!",
            "organization": org['name'],
            "new_member": user_id
        }), 200

    return jsonify({"error": "Invalid invite token"}), 403

# === BONUS: Some proper endpoints for comparison ===

@app.route('/api/me', methods=['GET'])
@login_required
def get_current_user_profile():
    """SECURE: Only returns current user's profile"""
    current_user_id = get_current_user()
    if current_user_id in users_db:
        user = users_db[current_user_id].copy()
        del user['password']  # Don't leak password
        return jsonify(user), 200
    return jsonify({"error": "User not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
