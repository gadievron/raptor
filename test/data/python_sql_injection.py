"""
Sample vulnerable Python code - SQL Injection
Used for testing RAPTOR scan, agentic, and analyze modes
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)

# VULNERABLE: SQL injection in database query
@app.route('/user/<user_id>')
def get_user(user_id):
    """Get user by ID - VULNERABLE to SQL injection"""
    db = sqlite3.connect(':memory:')
    cursor = db.cursor()

    # Direct string concatenation - SQL injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

    return cursor.fetchone()


# VULNERABLE: Hardcoded credentials
DATABASE_PASSWORD = "admin123!SuperSecret"

@app.route('/login', methods=['POST'])
def login():
    """Login endpoint - VULNERABLE to hardcoded password"""
    username = request.form.get('username')
    password = request.form.get('password')

    # Hardcoded password comparison
    if password == DATABASE_PASSWORD:
        return "Login successful"
    return "Login failed"


# VULNERABLE: Weak cryptography
import hashlib

def hash_password(password):
    """Hash password - VULNERABLE: MD5 is cryptographically weak"""
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABLE: Command injection
import subprocess

@app.route('/convert', methods=['POST'])
def convert_file():
    """Convert file format - VULNERABLE to command injection"""
    filename = request.form.get('filename')

    # Direct command execution - command injection vulnerability
    result = subprocess.run(f"convert {filename} output.jpg", shell=True)

    return "Conversion complete"


# VULNERABLE: Path traversal
@app.route('/download/<file_path>')
def download_file(file_path):
    """Download file - VULNERABLE to path traversal"""
    # No validation of file_path
    with open(f"/var/www/files/{file_path}", "rb") as f:
        return f.read()


if __name__ == '__main__':
    app.run(debug=True)
