# IDOR Vulnerable Test API

A deliberately vulnerable Flask API for testing IDOR (Insecure Direct Object References) detection tools.

## 🚨 WARNING
This application contains INTENTIONAL security vulnerabilities. DO NOT deploy in production or on public internet without proper isolation!

## Features

### Vulnerable Endpoints (IDOR Issues):
- ✅ **User Profile IDOR** - Access any user's profile
- ✅ **Document Access IDOR** - Read any user's private documents  
- ✅ **Organization IDOR** - View any organization details
- ✅ **Invite Token Takeover** - Critical IDOR like HackLido blog post
- ✅ **Privilege Escalation** - Update any user's role to admin

## Quick Start (Local Testing)

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python vulnerable_idor_app.py

# Access at http://localhost:5000
```

## Test Credentials

| Username | Password | User ID | Role |
|----------|----------|---------|------|
| alice | pass123 | 1 | user |
| bob | pass456 | 2 | user |
| admin | admin123 | 3 | admin |

## Testing with Your IDOR Fuzzer

### Step 1: Login as Two Different Users

**Login as Alice (User A):**
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"pass123"}'
```
Response: `{"token": "ALICE_TOKEN_HERE"}`

**Login as Bob (User B):**
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"pass456"}'
```
Response: `{"token": "BOB_TOKEN_HERE"}`

### Step 2: Configure Your Burp IDOR Fuzzer

In Configuration Tab:
- **User A**: `Authorization: Bearer ALICE_TOKEN_HERE`
- **User B**: `Authorization: Bearer BOB_TOKEN_HERE`

### Step 3: Test IDOR Vulnerabilities

**Test 1: User Profile IDOR**
```http
GET /api/users/1 HTTP/1.1
Host: localhost:5000
Authorization: Bearer ALICE_TOKEN
```
- Send to IDOR Fuzzer
- Your tool swaps to BOB_TOKEN
- Should detect Bob accessing Alice's profile (with API key leak!)

**Test 2: Document Access IDOR**
```http
GET /api/documents/1 HTTP/1.1
Host: localhost:5000
Authorization: Bearer ALICE_TOKEN
```
- Contains Alice's secret password
- Bob should NOT access this
- Your tool should flag unauthorized access

**Test 3: Organization Invite Token IDOR (Critical!)**
```http
PUT /api/organizations/1/invite HTTP/1.1
Host: localhost:5000
Authorization: Bearer ALICE_TOKEN
Content-Type: application/json
```
- This is the HackLido vulnerability scenario!
- Alice can copy her own org invite token (normal)
- Bob accessing this endpoint should get Alice's invite token (CRITICAL IDOR)
- Your tool should flag this as HIGH SEVERITY

**Test 4: Privilege Escalation via IDOR**
```http
PUT /api/users/2 HTTP/1.1
Host: localhost:5000
Authorization: Bearer ALICE_TOKEN
Content-Type: application/json

{"role": "admin"}
```
- Alice updating Bob's role to admin
- Should be blocked but isn't (IDOR + Privilege Escalation)

## Expected Tool Detections

Your IDOR Fuzzer should flag:

✅ **GET /api/users/{id}** - Status 200→200, API key in response  
✅ **GET /api/documents/{id}** - Status 200→200, sensitive content leak  
✅ **PUT /api/organizations/{id}/invite** - Status 200→200, invite_token in response  
✅ **GET /api/organizations/{id}/members** - Status 200→200, member list leak  
✅ **PUT /api/users/{id}** - Status 200→200, cross-user modification  

## Free Hosting Options

### Option 1: Render.com (Recommended)
```bash
# 1. Create free account at render.com
# 2. New Web Service → Connect GitHub repo
# 3. Build Command: pip install -r requirements.txt
# 4. Start Command: gunicorn vulnerable_idor_app:app
# 5. Deploy!
```

### Option 2: Railway.app
```bash
# 1. Install Railway CLI: npm i -g @railway/cli
# 2. Login: railway login
# 3. Deploy: railway up
```

### Option 3: PythonAnywhere
```bash
# 1. Sign up at pythonanywhere.com (free tier)
# 2. Upload vulnerable_idor_app.py
# 3. Create new web app (Flask)
# 4. Configure WSGI file to import app
```

### Option 4: Fly.io
```bash
# 1. Install flyctl
# 2. fly launch
# 3. fly deploy
```

## API Endpoints Reference

### Authentication
- `POST /api/login` - Login (returns token)
- `GET /api/logout` - Logout
- `GET /` - API documentation

### Vulnerable Endpoints
- `GET /api/users/<id>` - View user profile (IDOR)
- `PUT /api/users/<id>` - Update user (IDOR + Privilege Escalation)
- `GET /api/documents/<id>` - Access documents (IDOR)
- `GET /api/organizations/<id>` - View organization (IDOR)
- `PUT /api/organizations/<id>/invite` - Get invite token (Critical IDOR)
- `GET /api/organizations/<id>/members` - View members (IDOR)
- `POST /api/organizations/<id>/join` - Join with token

### Secure Endpoint (for comparison)
- `GET /api/me` - Get current user (properly implemented)

## Environment Variables (Optional)

```bash
FLASK_ENV=development
FLASK_DEBUG=1
```

## License

MIT - This is for educational/testing purposes only!
