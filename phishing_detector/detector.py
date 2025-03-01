import re
import requests
import base64
import mysql.connector
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import getpass
import hashlib
import tldextract
from difflib import SequenceMatcher
from requests.adapters import HTTPAdapter, Retry

# ========================
# API Configuration
# ========================
GOOGLE_API_KEY = 'AIzaSyCLEfzN5iNYicBQa2jxXIuK9sbRD8zlRaE'
VIRUSTOTAL_API_KEY = 'Y9a84ae697039eda789300b83568043c165c2fb09789a70d82bb1f86667158dd2'

# ========================
# Database Configuration
# ========================
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'phishing_detector_db',
    'unix_socket': '/opt/lampp/var/mysql/mysql.sock'
}

current_user = None
LEGIT_DOMAINS = ['facebook.com', 'google.com', 'amazon.com', 'paypal.com']

# ========================
# Database Setup
# ========================
def create_database():
    """Initialize database and tables"""
    try:
        conn = mysql.connector.connect(
            host='localhost',
            user='root',
            password='',
            unix_socket='/opt/lampp/var/mysql/mysql.sock'
        )
        cursor = conn.cursor()
        
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        cursor.execute(f"USE {DB_CONFIG['database']}")
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )''')
        
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")

# ========================
# Authentication System
# ========================
def hash_password(password):
    """Secure password hashing"""
    salt = "phishing-detector-salt"
    return hashlib.sha256((salt + password).encode()).hexdigest()

def cli_register_user():
    print("\n=== Registration ===")
    username = input("Username: ").strip()
    email = input("Email: ").strip()
    password = getpass.getpass("Password: ")
    
    if not all([username, email, password]):
        print("All fields are required!")
        return False

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", 
                      (username, email))
        if cursor.fetchone():
            print("Username/email already exists!")
            return False
        
        hashed_pw = hash_password(password)
        cursor.execute("INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
                      (username, hashed_pw, email))
        
        conn.commit()
        print("Registration successful!")
        return True
    except mysql.connector.Error as err:
        print(f"Registration failed: {err}")
        return False
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

def cli_login_user():
    global current_user
    print("\n=== Login ===")
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user and user['password'] == hash_password(password):
            current_user = user
            print(f"Welcome {user['username']}!")
            return True
        print("Invalid credentials!")
        return False
    except mysql.connector.Error as err:
        print(f"Login error: {err}")
        return False
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

def gui_register_user(username, email, password):
    if not all([username, email, password]):
        return False, "All fields are required!"

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", 
                      (username, email))
        if cursor.fetchone():
            return False, "Username/email already exists!"
        
        hashed_pw = hash_password(password)
        cursor.execute("INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
                      (username, hashed_pw, email))
        
        conn.commit()
        return True, "Registration successful!"
    except mysql.connector.Error as err:
        return False, f"Registration failed: {err}"
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

def gui_login_user(username, password):
    global current_user
    if not username or not password:
        return False, "Username and password required!"

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user and user['password'] == hash_password(password):
            current_user = user
            return True, f"Welcome {user['username']}!"
        return False, "Invalid credentials!"
    except mysql.connector.Error as err:
        return False, f"Login error: {err}"
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()

# ========================
# Phishing Detection Logic
# ========================
def safe_request(url):
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=frozenset(['GET', 'HEAD'])
    )
    session.mount('https://', HTTPAdapter(max_retries=retries))
    
    try:
        response = session.get(
            url,
            timeout=15,
            verify=True,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124'}
        )
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"\n🔧 Connection Error: {str(e)}")
        return None

def analyze_url(url):
    features = {
        'uses_https': False,
        'url_length': 0,
        'has_at_symbol': False,
        'has_ip': False,
        'num_subdomains': 0,
        'suspicious_domain': False,
        'domain_age_days': -1
    }
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        
        features['uses_https'] = url.startswith('https://')
        features['url_length'] = len(url)
        features['has_at_symbol'] = '@' in url
        features['has_ip'] = bool(re.match(
            r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            hostname
        ))
        features['num_subdomains'] = 0 if features['has_ip'] else hostname.count('.') - 1

        # Domain similarity check
        extracted = tldextract.extract(url)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        for legit_domain in LEGIT_DOMAINS:
            ratio = SequenceMatcher(None, base_domain, legit_domain).ratio()
            if ratio > 0.8 and base_domain != legit_domain:
                features['suspicious_domain'] = True
                break

        # Domain age calculation
        domain_info = whois.whois(hostname)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
            
        if creation_date:
            features['domain_age_days'] = (datetime.now() - creation_date).days

    except Exception as e:
        print(f"⚠️ Error analyzing URL: {str(e)}")
        
    return features

def analyze_content(url):
    result = {
        'password_fields': 0,
        'suspicious_keywords': 0,
        'insecure_forms': 0,
        'page_fetch_failed': True
    }
    
    response = safe_request(url)
    if not response or not response.ok:
        return result
    
    try:
        result['page_fetch_failed'] = False
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Password fields
        result['password_fields'] = len(soup.find_all('input', {'type': 'password'}))
        
        # Insecure forms
        forms = soup.find_all('form')
        result['insecure_forms'] = len([
            form['action'] for form in forms 
            if form.get('action') and not form['action'].startswith('https')
        ])
        
        # Suspicious keywords
        keywords = ['login', 'verify', 'account', 'security', 'update',
                   'urgent', 'immediately', 'suspicious', 'confirm']
        text = soup.get_text().lower()
        result['suspicious_keywords'] = sum(text.count(kw) for kw in keywords)
        
    except Exception as e:
        print(f"⚠️ Content analysis error: {str(e)}")
        
    return result

def check_google_safe_browsing(url):
    if not GOOGLE_API_KEY:
        return False
    
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(
            f"{api_url}?key={GOOGLE_API_KEY}", 
            json=payload, 
            timeout=10
        )
        return response.status_code == 200 and 'matches' in response.json()
    except Exception as e:
        print(f"Google API Error: {e}")
        return False

def check_redirects(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=15)
        if response.history:
            original = tldextract.extract(url)
            final = tldextract.extract(response.url)
            return original.registered_domain != final.registered_domain
        return False
    except Exception:
        return False

def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return False
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=15
        )
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats['malicious'] > 2
        return False
    except Exception as e:
        print(f"VirusTotal Error: {e}")
        return False

def generate_report(url):
    report = {
        'url': url,
        'features': {
            'url': analyze_url(url),
            'content': analyze_content(url),
            'google_safe': check_google_safe_browsing(url),
            'redirects': check_redirects(url),
            'virustotal': check_virustotal(url)
        },
        'score': 0,
        'scoring_details': []
    }

    scoring_rules = [
        (report['features']['content']['page_fetch_failed'], 3, "Failed to fetch page content"),
        (not report['features']['url']['uses_https'], 2, "No HTTPS"),
        (report['features']['url']['has_at_symbol'], 2, "Contains @ symbol"),
        (report['features']['url']['suspicious_domain'], 3, "Suspicious domain similarity"),
        (report['features']['url']['domain_age_days'] < 30, 2, "New domain (<30 days)"),
        (report['features']['content']['password_fields'] > 0 and not report['features']['url']['uses_https'], 
         3, "Password fields on insecure page"),
        (report['features']['content']['suspicious_keywords'] > 3, 1, "Suspicious keywords"),
        (report['features']['content']['insecure_forms'] > 0, 2, "Insecure form submissions"),
        (report['features']['google_safe'], 3, "Google Safe Browsing alert"),
        (report['features']['redirects'], 2, "Suspicious redirects"),
        (report['features']['virustotal'], 3, "VirusTotal detection")
    ]

    for condition, points, reason in scoring_rules:
        if condition:
            report['score'] += points
            report['scoring_details'].append(f"{reason} (+{points})")

    report['verdict'] = "🔴 High Risk: Phishing Detected" if report['score'] >= 6 else \
                       "🟡 Warning: Suspicious Activity" if report['score'] >= 3 else \
                       "🟢 Likely Safe"
    return report

# ========================
# CLI Application Flow
# ========================
def auth_menu():
    while True:
        print("\n1. Login")
        print("2. Register")
        print("3. Exit")
        choice = input("Choose option: ").strip()
        
        if choice == '1':
            if cli_login_user():
                main_menu()
        elif choice == '2':
            cli_register_user()
        elif choice == '3':
            exit()
        else:
            print("Invalid choice!")

def main_menu():
    while True:
        print("\n=== Main Menu ===")
        print("1. Analyze URL")
        print("2. View History")
        print("3. Logout")
        choice = input("Choose option: ").strip()
        
        if choice == '1':
            url = input("\nEnter URL to analyze: ").strip()
            print("\nAnalyzing...")
            try:
                report = generate_report(url)
                display_report(report)
            except Exception as e:
                print(f"Error analyzing URL: {e}")
        elif choice == '2':
            print("\nHistory feature coming soon!")
        elif choice == '3':
            global current_user
            current_user = None
            print("Logged out successfully!")
            break
        else:
            print("Invalid choice!")

def display_report(report):
    print("\n" + "="*60)
    print(f"PHISHING ANALYSIS REPORT: {report['url']}")
    print("="*60)
    
    print("\n🔗 URL ANALYSIS")
    print(f"  HTTPS Enabled:     {'✅' if report['features']['url']['uses_https'] else '❌'}")
    print(f"  URL Length:        {report['features']['url']['url_length']} characters")
    print(f"  Contains IP:       {'✅' if report['features']['url']['has_ip'] else '❌'}")
    print(f"  Subdomains:        {report['features']['url']['num_subdomains']}")
    print(f"  Domain Age:        {report['features']['url']['domain_age_days'] if report['features']['url']['domain_age_days'] != -1 else 'Unknown'} days")
    
    print("\n📄 CONTENT ANALYSIS")
    if report['features']['content']['page_fetch_failed']:
        print("  🔴 Failed to fetch page content")
    else:
        print(f"  Password Fields:   {report['features']['content']['password_fields']}")
        print(f"  Suspicious Terms:  {report['features']['content']['suspicious_keywords']}")
        print(f"  Insecure Forms:    {report['features']['content']['insecure_forms']}")
    
    print("\n🌐 EXTERNAL CHECKS")
    print(f"  Google Safe:       {'❌ Flagged' if report['features']['google_safe'] else '✅ Clean'}")
    print(f"  Redirects Found:   {'✅ Yes' if report['features']['redirects'] else '❌ No'}")
    print(f"  VirusTotal:        {'❌ Flagged' if report['features']['virustotal'] else '✅ Clean'}")
    
    print("\n📊 RISK ASSESSMENT")
    print(f"  Total Score:       {report['score']}/9")
    print("  Score Breakdown:")
    for detail in report['scoring_details']:
        print(f"    - {detail}")
    
    print("\n📢 FINAL VERDICT")
    print(f"  {report['verdict']}")
    print("="*60 + "\n")

if __name__ == "__main__":
    create_database()
    print("\n" + "="*40)
    print("🛡️ Phishing Website Detector 🛡️")
    print("="*40)
    
    try:
        import tldextract
    except ImportError:
        print("\n⚠️ Installing required package: tldextract")
        import subprocess
        subprocess.run(['pip', 'install', 'tldextract'], check=True)
        import tldextract
    
    auth_menu()
