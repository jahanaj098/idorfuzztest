from flask import Flask, request, jsonify, make_response


app = Flask(__name__)


# Mock Database
users = {
    "101": {"name": "User A", "role": "user", "email": "usera@example.com", "secret": "A_SECRET_123"},
    "102": {"name": "User B", "role": "user", "email": "userb@example.com", "secret": "B_SECRET_456"},
    "999": {"name": "Admin", "role": "admin", "email": "admin@example.com", "secret": "ADMIN_KEY_XYZ"}
}


orders = {
    "5001": {"owner": "101", "item": "Laptop", "cost": 1000},
    "5002": {"owner": "102", "item": "Phone", "cost": 500}
}


# Session Management (Mock)
# In real life, this would be a secure token. Here it's just the user ID.
def get_current_user():
    user_id = request.cookies.get("session")
    if not user_id:
        return None
    return user_id


@app.route('/')
def home():
    return "IDOR Test Lab Running.\n\nUse:\n/login/101 (User A)\n/login/102 (User B)\n/profile/<id>\n/api/order (POST json)"


@app.route('/login/<id>')
def login(id):
    if id not in users:
        return "User not found", 404
    resp = make_response("Logged in as %s" % users[id]['name'])
    resp.set_cookie("session", id)
    return resp


# 1. CLASSIC NUMERIC IDOR
# Vulnerable: Checks if you are logged in, but NOT if you own the requested ID.
@app.route('/profile/<id>', methods=['GET'])
def get_profile(id):
    current_user = get_current_user()
    if not current_user:
        return "Unauthorized", 401

    # VULNERABILITY: No check if current_user == id
    if id in users:
        # Simulate different content for different users to test Similarity Analysis
        user_data = users[id].copy()
        user_data["timestamp"] = "123456789" # Dynamic content
        return jsonify(user_data)
    return "Profile not found", 404


# 2. JSON API IDOR
# Vulnerable: Accepts JSON body with ID, returns data without ownership check.
@app.route('/api/order', methods=['POST'])
def get_order():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True)
    if not data or 'order_id' not in data:
        return jsonify({"error": "Missing order_id"}), 400

    order_id = str(data['order_id'])

    # VULNERABILITY: Returns order even if current_user doesn't own it
    if order_id in orders:
        return jsonify(orders[order_id])

    return jsonify({"error": "Order not found"}), 404


# 3. HEADER BYPASS
@app.route('/admin/settings', methods=['GET'])
def admin_settings():
    current_user = get_current_user()

    # Fake check for admin
    is_admin = False
    if current_user == "999":
        is_admin = True

    # Header Bypass attempt
    if request.headers.get("X-Role") == "admin":
        is_admin = True

    if not is_admin:
        return "Forbidden: Admins Only", 403

    return jsonify({"settings": "SENSITIVE_ADMIN_CONFIG", "flag": "CTF{IDOR_MASTER}"})


if __name__ == '__main__':
    print("Starting Vulnerable App on port 5000...")
    app.run(debug=True, host='0.0.0.0', port=5000)
