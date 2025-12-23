import os
import joblib
import numpy as np
import pefile
from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.utils import secure_filename
from urllib.parse import urlparse # Required for URL features
from thrember.features import PEFeatureExtractor
from dynamic_engine import SandboxSimulator

app = Flask(__name__)

# --- CONFIGURATION ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'msi'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- LOAD MODELS ---
print("⚡ Loading MalGuard AI Models...")
try:
    pe_model = joblib.load("malware_model.pkl")
    print("   ✅ PE Malware Model Loaded")
except:
    print("   ❌ Error: malware_model.pkl not found")

try:
    url_model = joblib.load("url_model.pkl")
    print("   ✅ URL Phishing Model Loaded")
except:
    print("   ❌ Error: url_model.pkl not found")


# --- HELPER FUNCTIONS ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_url_features(url):
    parsed = urlparse(url)
    return np.array([
        len(url),
        len(parsed.netloc),
        url.count('.'),
        url.count('@'),
        1 if parsed.netloc.replace('.', '').isdigit() else 0,
        sum(c.isdigit() for c in url)
    ]).reshape(1, -1)

def get_file_metadata(filepath):
    """Extracts metadata for the dashboard graphs"""
    try:
        pe = pefile.PE(filepath)
        return {
            "sections": len(pe.sections),
            "imports": len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            "exports": len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            "size_kb": os.path.getsize(filepath) / 1024
        }
    except Exception:
        return {"sections": 0, "imports": 0, "exports": 0, "size_kb": 0}

# --- PAGE ROUTES ---

@app.route('/')
def landing_page():
    return render_template('landing.html')

@app.route('/research')
def research_page():
    return render_template('research.html')

@app.route('/static-analysis')
def static_analysis_page():
    """ The New Dedicated Static Analysis Dashboard """
    return render_template('static_analysis.html')


# ... (Keep existing imports)

# --- ADD THIS NEW ROUTE ---
@app.route('/dashboard')
def dashboard_page():
    """Main Command Center"""
    return render_template('dashboard.html')

# ... (Keep all other routes like static_analysis_page, predict_file, etc.)
# --- API ROUTES ---

@app.route('/about')
def about_page():
    return render_template('about.html')


@app.route('/awareness')
def awareness_page():
    return render_template('awareness.html')


@app.route('/predict_url', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'No URL provided'})

    try:
        # 1. Extract Features
        features = extract_url_features(url)
        
        # 2. Predict
        probability = url_model.predict_proba(features)[0][1]
        prediction = "MALICIOUS" if probability > 0.5 else "SAFE"
        
        return jsonify({
            'name': url,
            'type': 'URL SCAN',
            'prediction': prediction,
            'probability': round(probability * 100, 2),
            'metadata': {'sections': 1, 'imports': 1, 'size_kb': len(url)}, # Dummy data for graph
            'status': 'success'
        })
    except Exception as e:
        return jsonify({'error': str(e)})



@app.route('/dynamic-analysis')
def dynamic_analysis_page():
    return render_template('dynamic_analysis.html')

@app.route('/run_dynamic', methods=['POST'])
def run_dynamic():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            # 1. Initialize Simulator
            sandbox = SandboxSimulator(filepath)
            
            # 2. Run "Analysis"
            report = sandbox.generate_report()
            
            # 3. Clean up
            os.remove(filepath)
            
            return jsonify({
                "status": "success",
                "filename": filename,
                "logs": report['logs'],
                "behaviors": report['behavior_map'],
                "score": report['threat_score']
            })

        except Exception as e:
            return jsonify({'error': str(e)})

    return jsonify({'error': 'File type not allowed'})



@app.route('/predict_file', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            # 1. Get Metadata
            metadata = get_file_metadata(filepath)

            # 2. Extract Features
            with open(filepath, "rb") as f:
                file_bytes = f.read()
            
            extractor = PEFeatureExtractor()
            features = extractor.feature_vector(file_bytes)
            features_array = np.array(features).reshape(1, -1)

            # 3. Predict
            probability = pe_model.predict_proba(features_array)[0][1]
            prediction = "MALWARE" if probability > 0.5 else "BENIGN"
            
            # 4. Result
            result = {
                'name': filename,
                'type': 'BINARY SCAN',
                'prediction': prediction,
                'probability': round(probability * 100, 2),
                'metadata': metadata,
                'status': 'success'
            }
            
            os.remove(filepath)
            return jsonify(result)

        except Exception as e:
            return jsonify({'error': str(e)})

    return jsonify({'error': 'File type not allowed'})

if __name__ == '__main__':
    app.run(debug=True, port=8080)