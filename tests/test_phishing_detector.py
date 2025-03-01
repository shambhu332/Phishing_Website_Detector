import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import mysql.connector
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from phishing_detector.detector import (
    cli_register_user, cli_login_user,
    gui_register_user, gui_login_user,
    hash_password, create_database,
    analyze_url, analyze_content,
    check_google_safe_browsing,
    check_redirects, check_virustotal,
    generate_report
)

TEST_DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'test_phishing_detector_db',
    'unix_socket': '/opt/lampp/var/mysql/mysql.sock'
}

class TestDatabaseSetup(unittest.TestCase):
    @patch('mysql.connector.connect')
    def test_create_database(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        create_database()
        mock_cursor.execute.assert_any_call("CREATE DATABASE IF NOT EXISTS phishing_detector_db")
        mock_conn.commit.assert_called()

class TestAuthSystem(unittest.TestCase):
    def setUp(self):
        self.test_user = {
            'username': 'testuser',
            'password': 'TestPass123!',
            'email': 'test@example.com'
        }

    def test_hash_password(self):
        hashed = hash_password('password123')
        self.assertEqual(len(hashed), 64)
        self.assertNotEqual(hashed, hash_password('differentpass'))

    @patch('phishing_detector.detector.mysql.connector.connect')
    def test_gui_register_user(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None
        
        success, message = gui_register_user('newuser', 'new@example.com', 'password')
        self.assertTrue(success)
        mock_cursor.execute.assert_called()

    @patch('phishing_detector.detector.mysql.connector.connect')
    def test_gui_login_user(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock(dictionary=True)
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = {
            'username': 'testuser',
            'password': hash_password('validpass')
        }
        
        success, message = gui_login_user('testuser', 'validpass')
        self.assertTrue(success)

class TestCLIAuth(unittest.TestCase):
    @patch('builtins.input')
    @patch('getpass.getpass')
    @patch('phishing_detector.detector.mysql.connector.connect')
    def test_cli_register_flow(self, mock_connect, mock_getpass, mock_input):
        mock_input.side_effect = ['testuser', 'test@example.com']
        mock_getpass.return_value = 'TestPass123!'
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None
        
        result = cli_register_user()
        self.assertTrue(result)

    @patch('builtins.input')
    @patch('getpass.getpass')
    @patch('phishing_detector.detector.mysql.connector.connect')
    def test_cli_login_flow(self, mock_connect, mock_getpass, mock_input):
        mock_input.return_value = 'testuser'
        mock_getpass.return_value = 'TestPass123!'
        mock_conn = MagicMock()
        mock_cursor = MagicMock(dictionary=True)
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchone.return_value = {
            'username': 'testuser',
            'password': hash_password('TestPass123!')
        }
        
        result = cli_login_user()
        self.assertTrue(result)

class TestPhishingDetection(unittest.TestCase):
    @patch('phishing_detector.detector.requests.Session.get')
    def test_analyze_content(self, mock_get):
        mock_response = MagicMock()
        mock_response.text = '''
            <html>
                <input type="password">
                <form action="http://insecure.com">
                Security alert: Please verify your account
            </html>
        '''
        mock_response.ok = True
        mock_get.return_value = mock_response
        
        result = analyze_content('http://test.com')
        self.assertEqual(result['password_fields'], 1)
        self.assertGreaterEqual(result['suspicious_keywords'], 2)

    @patch('phishing_detector.detector.whois.whois')
    def test_domain_age_calculation(self, mock_whois):
        mock_domain = MagicMock()
        test_date = datetime.now() - timedelta(days=800)
        mock_domain.creation_date = [test_date]
        mock_whois.return_value = mock_domain
        
        features = analyze_url('http://test.com')
        self.assertAlmostEqual(features['domain_age_days'], 800, delta=1)

class TestReportGeneration(unittest.TestCase):
    @patch('phishing_detector.detector.check_google_safe_browsing')
    @patch('phishing_detector.detector.check_virustotal')
    def test_high_risk_verdict(self, mock_vt, mock_gsb):
        mock_gsb.return_value = True
        mock_vt.return_value = True
        
        report = generate_report('http://phishing-site.com')
        self.assertGreaterEqual(report['score'], 6)
        self.assertIn("High Risk", report['verdict'])

if __name__ == '__main__':
    conn = mysql.connector.connect(
        host=TEST_DB_CONFIG['host'],
        user=TEST_DB_CONFIG['user'],
        password=TEST_DB_CONFIG['password'],
        unix_socket=TEST_DB_CONFIG['unix_socket']
    )
    cursor = conn.cursor()
    cursor.execute(f"DROP DATABASE IF EXISTS {TEST_DB_CONFIG['database']}")
    cursor.execute(f"CREATE DATABASE {TEST_DB_CONFIG['database']}")
    conn.close()
    
    unittest.main(verbosity=2)  
