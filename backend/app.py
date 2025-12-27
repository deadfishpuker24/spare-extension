from flask import Flask, request, jsonify
from flask_cors import CORS
import xgboost as xgb
import numpy as np
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for Chrome extension

# Load model on startup
model = None

def load_model():
    global model
    try:
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Try multiple possible locations for the model
        possible_paths = [
            os.path.join(script_dir, "phishing_model.json"),  # Same folder as app.py
            os.path.join(script_dir, "..", "phishing_model.json"),  # Parent folder
            "phishing_model.json"  # Current working directory
        ]
        
        model_path = None
        for path in possible_paths:
            if os.path.exists(path):
                model_path = path
                break
        
        if model_path is None:
            print("❌ Could not find phishing_model.json")
            return False
            
        # Use Booster for raw XGBoost model format
        model = xgb.Booster()
        model.load_model(model_path)
        print(f"✅ Model loaded successfully from: {model_path}")
        return True
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return False

# Feature names in order (must match training)
FEATURE_NAMES = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
    'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
    'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
    'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space',
    'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
    'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
    'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
    'nb_subdomains', 'prefix_suffix', 'random_domain',
    'shortening_service', 'path_extension',
    'nb_redirection', 'nb_external_redirection', 'length_words_raw',
    'char_repeat', 'shortest_words_raw', 'shortest_word_host',
    'shortest_word_path', 'longest_words_raw', 'longest_word_host',
    'longest_word_path', 'avg_words_raw', 'avg_word_host',
    'avg_word_path', 'phish_hints', 'domain_in_brand',
    'brand_in_subdomain', 'brand_in_path', 'suspecious_tld',
    'statistical_report',
    'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks',
    'ratio_nullHyperlinks', 'nb_extCSS', 'ratio_intRedirection',
    'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors',
    'login_form', 'external_favicon', 'links_in_tags',
    'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh',
    'iframe', 'popup_window', 'safe_anchor', 'onmouseover',
    'right_clic', 'empty_title', 'domain_in_title',
    'domain_with_copyright'
]

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None
    })

@app.route('/predict', methods=['POST'])
def predict():
    """Predict if URL is phishing"""
    try:
        if model is None:
            return jsonify({
                'error': 'Model not loaded'
            }), 500

        data = request.json
        
        if 'features' not in data:
            return jsonify({
                'error': 'Missing features in request'
            }), 400

        features = data['features']
        
        # Validate feature count
        if len(features) != len(FEATURE_NAMES):
            return jsonify({
                'error': f'Expected {len(FEATURE_NAMES)} features, got {len(features)}'
            }), 400

        # Convert to DMatrix for Booster
        X = np.array(features).reshape(1, -1)
        dmatrix = xgb.DMatrix(X, feature_names=FEATURE_NAMES)
        
        # Get prediction (Booster returns raw scores, need sigmoid for probability)
        raw_pred = model.predict(dmatrix)[0]
        phishing_prob = float(1 / (1 + np.exp(-raw_pred)))  # sigmoid
        is_phishing = phishing_prob > 0.5
        
        return jsonify({
            'is_phishing': is_phishing,
            'confidence': phishing_prob,
            'class': 'phishing' if is_phishing else 'legitimate'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    """Detailed analysis with feature breakdown"""
    try:
        if model is None:
            return jsonify({'error': 'Model not loaded'}), 500

        data = request.json
        features = data['features']
        url = data.get('url', 'Unknown')
        
        # Validate
        if len(features) != len(FEATURE_NAMES):
            return jsonify({
                'error': f'Expected {len(FEATURE_NAMES)} features'
            }), 400

        # Predict using DMatrix for Booster
        X = np.array(features).reshape(1, -1)
        dmatrix = xgb.DMatrix(X, feature_names=FEATURE_NAMES)
        raw_pred = model.predict(dmatrix)[0]
        phishing_prob = float(1 / (1 + np.exp(-raw_pred)))  # sigmoid
        is_phishing = phishing_prob > 0.5
        
        # Get feature importance
        feature_importance = model.get_score(importance_type='weight')
        
        # Create feature analysis
        suspicious_features = []
        for i, (name, value) in enumerate(zip(FEATURE_NAMES, features)):
            # Flag suspicious features
            if name == 'ip' and value == 1:
                suspicious_features.append('IP address in URL')
            elif name == 'https_token' and value == 1:
                suspicious_features.append('Not using HTTPS')
            elif name == 'suspecious_tld' and value == 1:
                suspicious_features.append('Suspicious TLD')
            elif name == 'login_form' and value == 1:
                suspicious_features.append('Has login form')
            elif name == 'shortening_service' and value == 1:
                suspicious_features.append('URL shortener detected')
            elif name == 'phish_hints' and value > 2:
                suspicious_features.append(f'Phishing keywords found ({int(value)})')
        
        return jsonify({
            'url': url,
            'is_phishing': is_phishing,
            'confidence': phishing_prob,
            'class': 'phishing' if is_phishing else 'legitimate',
            'suspicious_features': suspicious_features[:5],  # Top 5
            'risk_level': 'HIGH' if phishing_prob > 0.8 else 'MEDIUM' if phishing_prob > 0.5 else 'LOW'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Phishing Detection API...")
    
    if load_model():
        print("Model ready for predictions")
        print("Server starting on http://localhost:5000")
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        print("⚠️  Server starting without model - predictions will fail")
        app.run(host='0.0.0.0', port=5000, debug=True)