# Python Security Patterns

OWASP Top 10 2025 기반 Python 취약점 패턴 및 수정 방법.

## A01: Broken Access Control

### 취약 패턴
```python
# Django - IDOR
def get_user(request, user_id):
    user = User.objects.get(id=user_id)  # No ownership check
    return JsonResponse(user.to_dict())

# Flask - SSRF
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)  # User-controlled URL
    return response.text
```

### 안전한 패턴
```python
# Django - IDOR Fixed
def get_user(request, user_id):
    if user_id != request.user.id and not request.user.is_staff:
        return HttpResponseForbidden()
    user = User.objects.get(id=user_id)
    return JsonResponse(user.to_dict())

# Flask - SSRF Fixed
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com']

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        return 'Invalid URL', 400
    response = requests.get(url, timeout=5)
    return response.text
```

## A02: Security Misconfiguration

### 취약 패턴
```python
# Flask debug mode
app.run(debug=True)

# Django DEBUG in production
DEBUG = True
ALLOWED_HOSTS = ['*']

# Exposing stack traces
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500
```

### 안전한 패턴
```python
# Flask production config
app.run(debug=False)

# Django production settings
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

# Django security settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000

# Generic error handling
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.exception('Unhandled exception')
    return 'An error occurred', 500
```

## A04: Cryptographic Failures

### 취약 패턴
```python
# Weak hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# Hardcoded secrets
SECRET_KEY = 'my-secret-key-123'
API_KEY = 'sk-1234567890'

# Insecure random
import random
token = ''.join(random.choices('abcdef0123456789', k=32))
```

### 안전한 패턴
```python
# Strong password hashing
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
is_valid = bcrypt.checkpw(password.encode(), password_hash)

# Or with passlib
from passlib.hash import argon2
password_hash = argon2.hash(password)
is_valid = argon2.verify(password, password_hash)

# Environment-based secrets
import os
SECRET_KEY = os.environ['SECRET_KEY']
API_KEY = os.environ['API_KEY']

# Secure random
import secrets
token = secrets.token_hex(32)
```

## A05: Injection

### 취약 패턴
```python
# SQL Injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)

# Command Injection
import os
os.system(f"convert {filename} output.png")

# SSTI (Server-Side Template Injection)
from flask import render_template_string
return render_template_string(request.args.get('template'))

# Path Traversal
with open(f"/uploads/{request.args.get('file')}") as f:
    return f.read()
```

### 안전한 패턴
```python
# Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Django ORM (safe by default)
User.objects.filter(id=user_id)

# Safe command execution
import subprocess
import shlex
allowed_formats = ['png', 'jpg', 'gif']
if format in allowed_formats:
    subprocess.run(['convert', input_path, output_path], check=True)

# Use static templates
from flask import render_template
return render_template('page.html', data=user_data)

# Path Traversal Prevention
import os
from werkzeug.utils import secure_filename

filename = secure_filename(request.args.get('file'))
filepath = os.path.join('/uploads', filename)
if not filepath.startswith('/uploads/'):
    abort(400)
```

## A07: Authentication Failures

### 취약 패턴
```python
# Plain text password comparison
if user.password == request.form['password']:
    session['user_id'] = user.id

# No rate limiting
@app.route('/login', methods=['POST'])
def login():
    # Direct authentication
    pass

# Weak session management
session.permanent = True
app.permanent_session_lifetime = timedelta(days=365)
```

### 안전한 패턴
```python
# Secure password verification
import bcrypt
if bcrypt.checkpw(password.encode(), user.password_hash):
    session.regenerate()  # Prevent session fixation
    session['user_id'] = user.id

# Rate limiting with Flask-Limiter
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    pass

# Secure session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)
```

## A08: Software/Data Integrity Failures

### 취약 패턴
```python
# Unsafe deserialization
import pickle
data = pickle.loads(request.data)  # Remote code execution!

# Unsafe YAML loading
import yaml
config = yaml.load(user_input)  # Can execute arbitrary code

# Unsafe eval
result = eval(request.args.get('expr'))
```

### 안전한 패턴
```python
# Use JSON instead of pickle
import json
data = json.loads(request.data)

# Safe YAML loading
import yaml
config = yaml.safe_load(user_input)

# Safe expression evaluation
import ast
def safe_eval(expr):
    tree = ast.parse(expr, mode='eval')
    for node in ast.walk(tree):
        if isinstance(node, (ast.Call, ast.Attribute)):
            raise ValueError('Unsafe expression')
    return eval(compile(tree, '<string>', 'eval'))
```

## A09: Security Logging Failures

### 취약 패턴
```python
# No logging
def login(username, password):
    if authenticate(username, password):
        return create_session()
    return None

# Logging sensitive data
print(f"Login attempt: {username}, {password}")  # Logs password!

# Using print instead of proper logging
print(f"Error: {e}")
```

### 안전한 패턴
```python
import logging
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

def login(username, password):
    result = authenticate(username, password)
    logger.info(
        "login_attempt",
        username=username,  # No password
        success=result is not None,
        ip=request.remote_addr
    )
    if result:
        logger.info("login_success", username=username)
    else:
        logger.warning("login_failure", username=username)
    return result
```

## A10: Mishandling Exceptional Conditions

### 취약 패턴
```python
# Catching all exceptions silently
try:
    process_data()
except:
    pass

# Exposing stack traces
@app.errorhandler(Exception)
def handle_error(e):
    return traceback.format_exc(), 500

# Unbounded recursion/iteration
def process_tree(node):
    for child in node.children:
        process_tree(child)  # No depth limit
```

### 안전한 패턴
```python
# Specific exception handling with logging
try:
    process_data()
except ValidationError as e:
    logger.warning("Validation failed", error=str(e))
    return {"error": "Invalid input"}, 400
except DatabaseError as e:
    logger.error("Database error", error=str(e))
    return {"error": "Service unavailable"}, 503

# Generic error response
@app.errorhandler(Exception)
def handle_error(e):
    logger.exception("Unhandled exception")
    return {"error": "An unexpected error occurred"}, 500

# Bounded recursion
def process_tree(node, depth=0, max_depth=100):
    if depth > max_depth:
        raise ValueError("Maximum depth exceeded")
    for child in node.children:
        process_tree(child, depth + 1, max_depth)
```
