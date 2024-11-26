from flask import render_template, request, redirect, url_for, flash, current_app
import os
import random
import string
from werkzeug.utils import secure_filename
import yara
from app import app

# Dynamically set the uploads folder relative to the project directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
RESULTS_FOLDER = os.path.join(BASE_DIR, 'results')
YARA_RULES = 'yara_rules'

ALLOWED_EXTENSIONS = {'pdf', 'txt', 'exe', 'docx', 'doc'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # Max file size: 5MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULTS_FOLDER'] = RESULTS_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the uploads and results folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to generate a random ID
def generate_random_id():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

# Function to analyze the file using YARA
def analyze_file_with_yara(file_path):
    try:
        # Construct the absolute path to the YARA rules file
        rule_file_path = os.path.abspath(os.path.join(BASE_DIR, YARA_RULES, 'rules.yar'))
        
        # Load YARA rules
        rules = yara.compile(filepath=rule_file_path)
        
        # Perform YARA analysis on the file
        matches = rules.match(file_path)
        if matches:
            return ['- Rule Matched: '+match.rule+'\n- Description: '+match.meta['description']+'\n' for match in matches]
        else:
            return ['No matches found']
    except Exception as e:
        return [f"Error during YARA analysis: {str(e)}"]


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/essaie', methods=['GET', 'POST'])
def essaie():
    message = None  # Variable to store the message
    analysis_results = None  # Variable to store YARA analysis results
    result_id = None  # Variable to store the result ID
    
    if request.method == 'POST':
        # Check if the POST request has the file part
        if 'file' not in request.files:
            message = "No file part in the request"
            return render_template('essaie.html', message=message)
        
        file = request.files['file']
        
        # If no file is selected, return an error
        if file.filename == '':
            message = "No file selected"
            return render_template('essaie.html', message=message)
        
        # Validate the file type
        if not allowed_file(file.filename):
            message = "Invalid file type. Only PDF, TXT, EXE, and DOCX are allowed."
            return render_template('essaie.html', message=message)
        
        # Use secure_filename to prevent directory traversal
        filename = secure_filename(file.filename)
        
        try:
            # Save the file to the uploads folder
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Perform YARA analysis
            analysis_results = analyze_file_with_yara(file_path)

            # Generate a random ID for the results page
            result_id = generate_random_id()
            result_path = os.path.join(app.config['RESULTS_FOLDER'], f"{result_id}.txt")

            # Save the analysis results in a file
            with open(result_path, 'w') as result_file:
                result_file.write('\n'.join(analysis_results))

            # Create the success message with a link to the results page
            message = f"File <b>{filename}</b> uploaded successfully! <a href='/results/{result_id}'>View results</a>"

        except Exception as e:
            message = f"An error occurred while saving the file: {str(e)}"
    
    return render_template('essaie.html', message=message)


@app.route('/results/<result_id>')
def show_results(result_id):
    if not result_id.isalnum():  
        return "Invalid result ID", 400

    result_file_path = os.path.join(app.config['RESULTS_FOLDER'], f"{result_id}.txt")
    
    if os.path.commonprefix([os.path.abspath(result_file_path), os.path.abspath(RESULTS_FOLDER)]) != os.path.abspath(RESULTS_FOLDER):
        return "Access denied", 403
    
    if os.path.exists(result_file_path):
        with open(result_file_path, 'r') as file:
            analysis_results = file.read()
        return render_template('results.html', result_id=result_id, analysis_results=analysis_results)
    else:
        return "Result not found", 404

# Error handler for files exceeding size limit
@app.errorhandler(413)
def request_entity_too_large(e):
    return render_template('essaie.html', message="File size exceeds the maximum allowed size of 5MB."), 413

@app.route('/contact')
def contact():
    return render_template('contact.html')