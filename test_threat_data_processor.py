import unittest
import os
from unittest.mock import patch, MagicMock
from threat_data_processor import ThreatDataProcessor

class TestThreatDataProcessor(unittest.TestCase):
    """
    Unit tests for ThreatDataProcessor class
    """
    
    def setUp(self):
        # Create mock for QueryHandler
        self.mock_db_handler = MagicMock()
        
        # Create an instance of the tested class
        self.processor = ThreatDataProcessor(self.mock_db_handler)
        
        # Create temporary threat file for tests
        self.test_threats_file = "test_threats.txt"
        with open(self.test_threats_file, "w") as f:
            f.write("Ransomware,2025-05-01,192.168.1.1,USA,01:30:00,500\n")
            f.write("Phishing,2025-05-02,192.168.1.2,Russia,00:45:30,200\n")
            f.write("DDoS,2025-05-03,192.168.1.3,China,02:15:45,0\n")
            f.write("Invalid line\n")  # Invalid line
        
        # Create temporary blacklist file for tests
        self.test_blacklist_file = "test_blacklist.txt"
        with open(self.test_blacklist_file, "w") as f:
            f.write("192.168.1.1\n")
            f.write("192.168.1.3\n")
    
    def tearDown(self):
        # Delete temporary files
        if os.path.exists(self.test_threats_file):
            os.remove(self.test_threats_file)
        
        if os.path.exists(self.test_blacklist_file):
            os.remove(self.test_blacklist_file)
    
    def test_validate_threat_format(self):
        # Test valid format
        valid_line = "Ransomware,2025-05-01,192.168.1.1,USA,01:30:00,500"
        self.assertTrue(self.processor.validate_threat_format(valid_line))
        
        # Test invalid format - missing fields
        invalid_line = "Ransomware,2025-05-01,192.168.1.1,USA,01:30:00"
        self.assertFalse(self.processor.validate_threat_format(invalid_line))
        
        # Test invalid format - too many fields
        invalid_line = "Ransomware,2025-05-01,192.168.1.1,USA,01:30:00,500,extra"
        self.assertFalse(self.processor.validate_threat_format(invalid_line))
    
    def test_parse_duration_to_seconds(self):
        # Test converting duration to seconds
        self.assertEqual(self.processor.parse_duration_to_seconds("01:30:00"), 5400)  # 1.5 hours
        self.assertEqual(self.processor.parse_duration_to_seconds("00:45:30"), 2730)  # 45.5 minutes
        self.assertEqual(self.processor.parse_duration_to_seconds("00:00:59"), 59)     # 59 seconds
    
    def test_process_threats_file(self):
        # Test processing the threats file
        threats_data = self.processor.process_threats_file(self.test_threats_file)
        
        # Check that 3 valid records were returned (out of 4 lines in the file)
        self.assertEqual(len(threats_data), 3)
        
        # Check the content of the first record
        first_threat = threats_data[0]
        self.assertEqual(first_threat["attack_type"], "Ransomware")
        self.assertEqual(first_threat["date"], "2025-05-01")
        self.assertEqual(first_threat["attacker_ip"], "192.168.1.1")
        self.assertEqual(first_threat["country"], "USA")
        self.assertEqual(first_threat["duration_sec"], 5400)  # 01:30:00 in seconds
        self.assertEqual(first_threat["data_leaked_mb"], 500)
        self.assertFalse(first_threat["is_investigated"])
    
    def test_create_attacks_table(self):
        # Test creating the attacks table
        self.processor.create_attacks_table()
        
        # Check that execute_non_fetch function was called with the appropriate query
        self.mock_db_handler.execute_non_fetch.assert_called_once()
        # Check that the query contains the words CREATE TABLE
        self.assertIn("CREATE TABLE", self.mock_db_handler.execute_non_fetch.call_args[0][0])
    
    def test_insert_threats_to_db(self):
        # Create threat data for testing
        threats_data = [
            {
                "attack_type": "Ransomware",
                "date": "2025-05-01",
                "attacker_ip": "192.168.1.1",
                "country": "USA",
                "duration_sec": 5400,
                "data_leaked_mb": 500,
                "is_investigated": False
            }
        ]
        
        # Run the tested function
        self.processor.insert_threats_to_db(threats_data)
        
        # Check that execute_non_fetch function was called once
        self.assertEqual(self.mock_db_handler.execute_non_fetch.call_count, 1)
        
        # Check that the query contains the word INSERT
        self.assertIn("INSERT", self.mock_db_handler.execute_non_fetch.call_args[0][0])
    
    def test_get_top_attacker_ips(self):
        # Define mock result for the query
        expected_result = [
            {"attacker_ip": "192.168.1.1", "attack_count": 5},
            {"attacker_ip": "192.168.1.2", "attack_count": 3}
        ]
        self.mock_db_handler.execute_fetch.return_value = expected_result
        
        # Run the tested function
        result = self.processor.get_top_attacker_ips(2)
        
        # Check that execute_fetch function was called with the correct parameters
        self.mock_db_handler.execute_fetch.assert_called_once()
        self.assertIn("LIMIT", self.mock_db_handler.execute_fetch.call_args[0][0])
        self.assertEqual(self.mock_db_handler.execute_fetch.call_args[0][1], (2,))
        
        # Check that the correct result was returned
        self.assertEqual(result, expected_result)
    
    def test_update_investigated_status(self):
        # Run the tested function
        self.processor.update_investigated_status(self.test_blacklist_file)
        
        # Check that execute_non_fetch function was called twice (for two IP addresses in the blacklist)
        self.assertEqual(self.mock_db_handler.execute_non_fetch.call_count, 2)
        
        # Check that the query contains the word UPDATE
        for call in self.mock_db_handler.execute_non_fetch.call_args_list:
            self.assertIn("UPDATE", call[0][0])


if __name__ == "__main__":
    unittest.main()