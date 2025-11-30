import unittest
from unittest.mock import patch, MagicMock
from db_adaptor import DatabaseAdapter

class TestDatabaseAdapter(unittest.TestCase):
    """Unit tests for DatabaseAdapter class"""
    
    def setUp(self):
        """Set up valid values for testing"""
        self.valid_host = "192.168.1.1"
        self.valid_database = "test_db"
        self.valid_user = "test_user"
        self.valid_password = "Password123!"
    
    def test_init_valid_credentials(self):
        # Test instance creation with valid connection credentials
        db_adapter = DatabaseAdapter(
            host=self.valid_host,
            db_name=self.valid_database,
            username=self.valid_user,
            password=self.valid_password
        )
        
        self.assertEqual(db_adapter.host, self.valid_host)
        self.assertEqual(db_adapter.db_name, self.valid_database)
        self.assertEqual(db_adapter.username, self.valid_user)
        self.assertEqual(db_adapter.password, self.valid_password)
        self.assertIsNone(db_adapter.connection)
    
    def test_init_invalid_host(self):
        # Test instance creation with invalid server address
        with self.assertRaises(AttributeError):
            DatabaseAdapter(
                host="invalid-host",  # Invalid address
                db_name=self.valid_database,
                username=self.valid_user,
                password=self.valid_password
            )
    
    def test_init_invalid_db_name(self):
        # Test instance creation with invalid database name
        with self.assertRaises(AttributeError):
            DatabaseAdapter(
                host=self.valid_host,
                db_name="invalid-db",  # Invalid database name
                username=self.valid_user,
                password=self.valid_password
            )
    
    def test_init_invalid_username(self):
        # Test instance creation with invalid username
        with self.assertRaises(AttributeError):
            DatabaseAdapter(
                host=self.valid_host,
                db_name=self.valid_database,
                username="invalid-user",  # Invalid username
                password=self.valid_password
            )
    
    @patch('db_adaptor.connect')
    def test_connect(self, mock_connect):
        # Create mock for database connection
        mock_connection = MagicMock()
        mock_connect.return_value = mock_connection
        
        # Create an instance of the class
        db_adapter = DatabaseAdapter(
            host=self.valid_host,
            db_name=self.valid_database,
            username=self.valid_user,
            password=self.valid_password
        )
        
        # Test the connection function
        db_adapter.connect()
        
        # Verify that connect function was called with correct parameters
        mock_connect.assert_called_once_with(
            host=self.valid_host,
            user=self.valid_user,
            password=self.valid_password,
            db=self.valid_database,
            cursorclass=unittest.mock.ANY  # Not checking the exact cursor type
        )
        
        # Verify that connection was stored in the appropriate variable
        self.assertEqual(db_adapter.connection, mock_connection)

    def test_disconnect(self):
        # Create an instance of the class
        db_adapter = DatabaseAdapter(
            host=self.valid_host,
            db_name=self.valid_database,
            username=self.valid_user,
            password=self.valid_password
        )
        
        # Create mock for connection
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value = mock_cursor
        db_adapter.connection = mock_connection
        
        # Test the disconnect function
        db_adapter.disconnect()
        
        # Verify that the correct functions were called
        mock_cursor.close.assert_called_once()
        mock_connection.close.assert_called_once()
        
        # Verify that connection was reset
        self.assertIsNone(db_adapter.connection)
    
    def test_disconnect_no_connection(self):
        # Create an instance of the class without active connection
        db_adapter = DatabaseAdapter(
            host=self.valid_host,
            db_name=self.valid_database,
            username=self.valid_user,
            password=self.valid_password
        )
        
        # Verify no error when trying to disconnect without active connection
        db_adapter.disconnect()  # Should not raise an error


if __name__ == "__main__":
    unittest.main()