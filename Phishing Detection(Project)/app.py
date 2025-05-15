from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import psutil
import re
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)
CORS(app)

def get_system_metrics():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        'cpu_usage': cpu_percent,
        'memory_usage': memory.percent,
        'disk_usage': disk.percent,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

def analyze_phishing_indicators(url, system_metrics):
    # Parse the URL properly
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
    except Exception:
        domain = url.lower()
        path = ''
        query = ''

    # List of legitimate TLDs
    legitimate_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.mil', '.int', '.eu', '.us', '.uk', '.ca', '.au', '.de', '.fr', '.jp'}
    
    # List of suspicious TLDs
    suspicious_tlds = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.top', '.work', '.party', '.date', '.stream', '.racing', '.win', '.bid', '.loan'}
    
    # Extract TLD from domain
    tld = '.'+domain.split('.')[-1] if '.' in domain else ''
    
    # List of common brand names to check for typosquatting
    brand_names = {
        'google': 'google.com',
        'facebook': 'facebook.com',
        'microsoft': 'microsoft.com',
        'apple': 'apple.com',
        'amazon': 'amazon.com',
        'paypal': 'paypal.com',
        'netflix': 'netflix.com',
        'instagram': 'instagram.com',
        'twitter': 'twitter.com',
        'linkedin': 'linkedin.com'
    }

    # Enhanced phishing detection indicators
    indicators = {
        # Suspicious TLD check (high weight)
        'suspicious_tld': (tld in suspicious_tlds) or (tld not in legitimate_tlds),
        
        # IP address instead of domain name
        'ip_address': bool(re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$', domain)),
        
        # Suspicious ports
        'suspicious_ports': ':' in domain and domain.split(':')[-1].isdigit() and int(domain.split(':')[-1]) not in [80, 443],
        
        # System resource anomalies
        'system_anomaly': system_metrics['cpu_usage'] > 90 or system_metrics['memory_usage'] > 90,
        
        # URL length (phishing URLs tend to be longer)
        'long_url': len(url) > 100,
        
        # Suspicious characters in domain
        'suspicious_chars': bool(re.search(r'[0-9]|[-]', domain.split('.')[0])) if '.' in domain else False,
        
        # Multiple subdomains (more than 3 levels)
        'multiple_subdomains': domain.count('.') > 2,
        
        # Suspicious keywords in path or query
        'suspicious_keywords': any(keyword in (path + query) for keyword in [
            'login', 'signin', 'verify', 'account', 'secure', 'update', 'password',
            'confirm', 'verification', 'authenticate', 'wallet', 'security'
        ]),
        
        # Brand name typosquatting detection
        'brand_impersonation': any(
            brand in domain and brand_names[brand] not in domain 
            for brand in brand_names
        ),
        
        # Special characters in domain
        'special_chars': bool(re.search(r'[^a-zA-Z0-9.-]', domain)),
        
        # Numeric domain
        'numeric_domain': bool(re.search(r'^[0-9]+', domain.split('.')[0])),
        
        # Suspicious domain patterns
        'suspicious_patterns': bool(re.search(r'(secure|login|account|update|verify)[0-9]', domain))
    }
    
    # Calculate weighted risk score with adjusted weights
    weights = {
        'suspicious_tld': 0.25,          # Higher weight for suspicious TLD
        'ip_address': 0.15,
        'suspicious_ports': 0.10,
        'system_anomaly': 0.05,
        'long_url': 0.05,
        'suspicious_chars': 0.10,
        'multiple_subdomains': 0.05,
        'suspicious_keywords': 0.10,
        'brand_impersonation': 0.20,     # Higher weight for brand impersonation
        'special_chars': 0.10,
        'numeric_domain': 0.10,
        'suspicious_patterns': 0.15
    }
    
    risk_score = sum(indicators[key] * weights[key] for key in weights) * 100
    
    # Ensure the risk score is between 0 and 100
    risk_score = min(max(risk_score, 0), 100)
    
    # Increase risk score if multiple high-risk indicators are present
    high_risk_count = sum(1 for key in ['suspicious_tld', 'ip_address', 'brand_impersonation', 'suspicious_patterns'] if indicators[key])
    if high_risk_count >= 2:
        risk_score = min(risk_score * 1.5, 100)  # Increase score by 50% if multiple high-risk indicators

    return indicators, risk_score

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/system-metrics')
def system_metrics():
    return jsonify(get_system_metrics())

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url', '')
    system_metrics = get_system_metrics()
    
    try:
        indicators, risk_score = analyze_phishing_indicators(url, system_metrics)
        
        return jsonify({
            'indicators': indicators,
            'risk_score': risk_score,
            'system_metrics': system_metrics,
            'analyzed_url': url
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'risk_score': 0,
            'system_metrics': system_metrics
        }), 400

if __name__ == '__main__':
    app.run(debug=True) 