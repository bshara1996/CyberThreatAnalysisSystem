import unittest
import os
import tempfile
from unittest.mock import patch, MagicMock
from activity_log_analyzer import ActivityLogAnalyzer

class TestActivityLogAnalyzer(unittest.TestCase):
    """Unit tests for ActivityLogAnalyzer class"""
    
    def setUp(self):
        """Setup before each test - creating a temporary log file"""
        # Create a temporary log file for testing with CSV format
        self.temp_log_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_log_file.write(b"192.168.1.1, 2023-01-01 10:00:00, LOGIN, SUCCESS\n")
        self.temp_log_file.write(b"192.168.1.2, 2023-01-01 10:01:00, LOGIN, SUCCESS\n")
        self.temp_log_file.write(b"192.168.1.1, 2023-01-01 10:02:00, ADMIN_ACCESS, SUCCESS\n")
        self.temp_log_file.write(b"192.168.1.3, 2023-01-01 10:03:00, LOGIN, FAILURE\n")
        self.temp_log_file.write(b"192.168.1.3, 2023-01-01 10:04:00, LOGIN, FAILURE\n")
        self.temp_log_file.write(b"192.168.1.4, 2023-01-01 10:05:00, FILE_DOWNLOAD, SUCCESS\n")
        self.temp_log_file.write(b"192.168.1.5, 2023-01-01 10:06:00, LOGIN, FAILURE\n")
        self.temp_log_file.close()
        
        # Create temporary output files
        self.temp_activity_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_activity_file.close()
        
        self.temp_ips_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_ips_file.close()
        
        # Create an instance of the tested class
        self.analyzer = ActivityLogAnalyzer(self.temp_log_file.name)
    
    def tearDown(self):
        """Cleanup after each test - delete temporary files"""
        os.unlink(self.temp_log_file.name)
        if os.path.exists(self.temp_activity_file.name):
            os.unlink(self.temp_activity_file.name)
        if os.path.exists(self.temp_ips_file.name):
            os.unlink(self.temp_ips_file.name)
    
    def test_init(self):
        """Test proper initialization of the class"""
        self.assertEqual(self.analyzer.log_file, self.temp_log_file.name)
    
    def test_parse_log_line_valid(self):
        """Test log line parsing function with valid CSV format"""
        line = '192.168.1.1, 2023-01-01 10:00:00, LOGIN, SUCCESS'
        result = self.analyzer.parse_log_line(line)
        
        self.assertEqual(result['ip'], '192.168.1.1')
        self.assertEqual(result['timestamp'], '2023-01-01 10:00:00')
        self.assertEqual(result['action'], 'LOGIN')
        self.assertEqual(result['result'], 'SUCCESS')
    
    def test_parse_log_line_invalid(self):
        """Test log line parsing function with invalid format"""
        line = '192.168.1.1, 2023-01-01 10:00:00, LOGIN'  # Missing result
        result = self.analyzer.parse_log_line(line)
        
        self.assertEqual(result, {})
    
    def test_is_suspicious_failure(self):
        """Test identification of suspicious activity - FAILURE result"""
        log_entry = {
            'ip': '192.168.1.1',
            'timestamp': '2023-01-01 10:00:00',
            'action': 'LOGIN',
            'result': 'FAILURE'
        }
        result = self.analyzer.is_suspicious(log_entry)
        self.assertTrue(result)
    
    def test_is_suspicious_success(self):
        """Test identification of suspicious activity - SUCCESS result"""
        log_entry = {
            'ip': '192.168.1.1',
            'timestamp': '2023-01-01 10:00:00',
            'action': 'LOGIN',
            'result': 'SUCCESS'
        }
        result = self.analyzer.is_suspicious(log_entry)
        self.assertFalse(result)
    
    def test_analyze_logs(self):
        """Test log analysis functionality"""
        suspicious_entries, suspicious_ips = self.analyzer.analyze_logs()
        
        # Check that suspicious activities were identified (FAILURE entries)
        self.assertEqual(len(suspicious_entries), 3)
        
        # Check that suspicious IPs were identified
        self.assertEqual(len(suspicious_ips), 2)  # 192.168.1.3 and 192.168.1.5
        
        # Check specific IPs
        self.assertIn('192.168.1.3', suspicious_ips)
        self.assertIn('192.168.1.5', suspicious_ips)
        
        # Check that entries have correct structure
        for entry in suspicious_entries:
            self.assertIn('ip', entry)
            self.assertIn('timestamp', entry)
            self.assertIn('action', entry)
            self.assertIn('result', entry)
            self.assertEqual(entry['result'], 'FAILURE')
    
    def test_save_suspicious_activity(self):
        """Test saving suspicious activities to file"""
        # Call the tested function
        self.analyzer.save_suspicious_activity(self.temp_activity_file.name)
        
        # Check that the file was created and contains the expected content
        self.assertTrue(os.path.exists(self.temp_activity_file.name))
        
        with open(self.temp_activity_file.name, 'r') as file:
            content = file.read()
        
        # Should contain the 3 suspicious entries from our test data
        self.assertIn("192.168.1.3, 2023-01-01 10:03:00, LOGIN, FAILURE", content)
        self.assertIn("192.168.1.3, 2023-01-01 10:04:00, LOGIN, FAILURE", content)
        self.assertIn("192.168.1.5, 2023-01-01 10:06:00, LOGIN, FAILURE", content)
        
        # Count the lines to verify we have 3 entries
        lines = content.strip().split('\n')
        self.assertEqual(len(lines), 3)
    
    def test_save_suspicious_ips(self):
        """Test saving suspicious IPs to file"""
        # Call the tested function
        self.analyzer.save_suspicious_ips(self.temp_ips_file.name)
        
        # Check that the file was created and contains the expected content
        self.assertTrue(os.path.exists(self.temp_ips_file.name))
        
        with open(self.temp_ips_file.name, 'r') as file:
            content = file.read()
        
        # Should contain the 2 suspicious IPs from our test data
        self.assertIn("192.168.1.3", content)
        self.assertIn("192.168.1.5", content)
        
        # Count the lines to verify we have 2 unique IPs
        lines = content.strip().split('\n')
        self.assertEqual(len(lines), 2)
    
    def test_analyze_logs_empty_file(self):
        """Test analysis with empty log file"""
        # Create empty log file
        empty_log_file = tempfile.NamedTemporaryFile(delete=False)
        empty_log_file.close()
        
        analyzer = ActivityLogAnalyzer(empty_log_file.name)
        suspicious_entries, suspicious_ips = analyzer.analyze_logs()
        
        self.assertEqual(len(suspicious_entries), 0)
        self.assertEqual(len(suspicious_ips), 0)
        
        # Cleanup
        os.unlink(empty_log_file.name)
    
    def test_analyze_logs_malformed_lines(self):
        """Test analysis with malformed log lines"""
        # Create log file with malformed lines
        malformed_log_file = tempfile.NamedTemporaryFile(delete=False)
        malformed_log_file.write(b"192.168.1.1, 2023-01-01 10:00:00, LOGIN, SUCCESS\n")
        malformed_log_file.write(b"malformed line\n")
        malformed_log_file.write(b"192.168.1.2, 2023-01-01 10:01:00, LOGIN, FAILURE\n")
        malformed_log_file.write(b"another,malformed,line\n")
        malformed_log_file.close()
        
        analyzer = ActivityLogAnalyzer(malformed_log_file.name)
        suspicious_entries, suspicious_ips = analyzer.analyze_logs()
        
        # Should only find 1 suspicious entry (the FAILURE one)
        self.assertEqual(len(suspicious_entries), 1)
        self.assertEqual(len(suspicious_ips), 1)
        self.assertIn('192.168.1.2', suspicious_ips)
        
        # Cleanup
        os.unlink(malformed_log_file.name)


if __name__ == "__main__":
    unittest.main()