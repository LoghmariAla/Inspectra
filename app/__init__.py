from flask import Flask
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['YARA_RULES_FOLDER'] = 'yara_rules'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'exe', 'docx'}
# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Import and register routes
from app import routes


