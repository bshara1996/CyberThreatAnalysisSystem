import unittest
from credentials_validator import CredentialsValidator

class TestCredentialsValidator(unittest.TestCase):
    """Unit tests for CredentialsValidator class"""
    
    def test_validate_ipv4(self):
        # Test valid IP addresses
        self.assertTrue(CredentialsValidator.validate_ipv4("192.168.1.1"))
        self.assertTrue(CredentialsValidator.validate_ipv4("10.0.0.1"))
        self.assertTrue(CredentialsValidator.validate_ipv4("172.16.0.1"))
        
        # Test invalid IP addresses
        self.assertFalse(CredentialsValidator.validate_ipv4("256.168.1.1"))  # Octet value too large
        self.assertFalse(CredentialsValidator.validate_ipv4("192.168.1"))     # Missing octet
        self.assertFalse(CredentialsValidator.validate_ipv4("192.168.1.1.1"))  # Too many octets
        self.assertFalse(CredentialsValidator.validate_ipv4("192.168.1.a"))    # Invalid character
        self.assertFalse(CredentialsValidator.validate_ipv4(123))              # Not a string
    
    def test_validate_ipv4_format(self):
        # Test valid IP address formats
        self.assertTrue(CredentialsValidator.validate_ipv4_format("192.168.1.1"))
        self.assertTrue(CredentialsValidator.validate_ipv4_format("255.255.255.255"))
        
        # Test invalid IP address formats
        self.assertFalse(CredentialsValidator.validate_ipv4_format("192.168.1"))     # Missing octet
        self.assertFalse(CredentialsValidator.validate_ipv4_format("192.168.1.1.1"))  # Too many octets
        self.assertFalse(CredentialsValidator.validate_ipv4_format("192.168.1.a"))    # Invalid character
        self.assertFalse(CredentialsValidator.validate_ipv4_format(123))              # Not a string
    
    def test_validate_database_name(self):
        # Test valid database names
        self.assertTrue(CredentialsValidator.validate_database_name("my_database"))
        self.assertTrue(CredentialsValidator.validate_database_name("database123"))
        self.assertTrue(CredentialsValidator.validate_database_name("db$name"))
        
        # Test invalid database names
        self.assertFalse(CredentialsValidator.validate_database_name("my-database"))  # Contains invalid character
        self.assertFalse(CredentialsValidator.validate_database_name("my database"))  # Contains space
        self.assertFalse(CredentialsValidator.validate_database_name(123))            # Not a string
    
    def test_validate_username(self):
        # Test valid usernames
        self.assertTrue(CredentialsValidator.validate_username("admin"))
        self.assertTrue(CredentialsValidator.validate_username("db_user"))
        self.assertTrue(CredentialsValidator.validate_username("_user"))
        
        # Test invalid usernames
        self.assertFalse(CredentialsValidator.validate_username("user123"))      # Contains numbers
        self.assertFalse(CredentialsValidator.validate_username("user-name"))    # Contains invalid character
        self.assertFalse(CredentialsValidator.validate_username("user name"))    # Contains space
        self.assertFalse(CredentialsValidator.validate_username(123))            # Not a string


if __name__ == "__main__":
    unittest.main()