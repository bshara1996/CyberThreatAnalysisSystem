import unittest
from unittest.mock import patch, MagicMock
from query_handler import QueryHandler
from db_adaptor import DatabaseAdapter

class TestQueryHandler(unittest.TestCase):
    """
    Unit tests for QueryHandler class
    """
    
    def setUp(self):
        # Define valid values for tests
        self.valid_host = "localhost"
        self.valid_db_name = "test_db"
        self.valid_username = "admin"
        self.valid_password = "password"
        
        # Create a patch for the base class
        self.db_adapter_patcher = patch('query_handler.DatabaseAdapter')
        self.mock_db_adapter = self.db_adapter_patcher.start()
        
        # Create an instance of the tested class with mocked connect and disconnect functions
        with patch.object(QueryHandler, 'connect'), patch.object(QueryHandler, 'disconnect'):
            self.query_handler = QueryHandler(
                host=self.valid_host,
                db_name=self.valid_db_name,
                username=self.valid_username,
                password=self.valid_password
            )
            
        # Set up a mock connection
        self.query_handler.connection = MagicMock()
    
    def tearDown(self):
        # Stop the patch
        self.db_adapter_patcher.stop()
    
    def test_init(self):
        # Check that the class was initialized correctly
        self.assertEqual(self.query_handler.host, self.valid_host)
        self.assertEqual(self.query_handler.db_name, self.valid_db_name)
        self.assertEqual(self.query_handler.username, self.valid_username)
    
    @patch('query_handler.QueryHandler.connect')
    @patch('query_handler.QueryHandler.disconnect')
    def test_execute_fetch(self, mock_disconnect, mock_connect):
        # Define query and conditions for testing
        query = "SELECT * FROM users WHERE id = %s"
        conditions = (1,)
        expected_result = [{"id": 1, "name": "Test User"}]
        
        # Create mocks for connection and cursor
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = expected_result
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor
        
        # Set the mock connection
        self.query_handler.connection = mock_connection
        
        # Run the tested function
        result = self.query_handler.execute_fetch(query, conditions)
        
        # Assertions
        mock_connect.assert_called_once()
        mock_cursor.execute.assert_called_once_with(query, conditions)
        mock_cursor.fetchall.assert_called_once()
        mock_disconnect.assert_called_once()
        self.assertEqual(result, expected_result)
    
    def test_execute_fetch_invalid_args(self):
        # Test error when invalid parameters are passed
        with self.assertRaises(ValueError):
            self.query_handler.execute_fetch(123, (1,))  # Invalid query
        
        with self.assertRaises(ValueError):
            self.query_handler.execute_fetch("SELECT * FROM users", "invalid")  # Invalid conditions
    
    @patch('query_handler.QueryHandler.connect')
    def test_execute_fetch_runtime_error(self, mock_connect):
        # Set up mock to throw an error
        mock_connect.side_effect = RuntimeError("Connection error")
        
        # Check that the error is propagated
        with self.assertRaises(RuntimeError):
            self.query_handler.execute_fetch("SELECT * FROM users", ())
    
    @patch('query_handler.QueryHandler.connect')
    @patch('query_handler.QueryHandler.disconnect')
    def test_execute_non_fetch(self, mock_disconnect, mock_connect):
        # Define query and conditions for testing
        query = "INSERT INTO users (name) VALUES (%s)"
        conditions = ("Test User",)
        
        # Create mocks for connection and cursor
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_connection.cursor.return_value = mock_cursor
        
        # Set the mock connection
        self.query_handler.connection = mock_connection
        
        # Run the tested function
        self.query_handler.execute_non_fetch(query, conditions)
        
        # Assertions
        mock_connect.assert_called_once()
        mock_cursor.execute.assert_called_once_with(query, conditions)
        mock_connection.commit.assert_called_once()
        mock_disconnect.assert_called_once()
    
    def test_execute_non_fetch_invalid_args(self):
        # Test error when invalid parameters are passed
        with self.assertRaises(ValueError):
            self.query_handler.execute_non_fetch(123, (1,))  # Invalid query
        
        with self.assertRaises(ValueError):
            self.query_handler.execute_non_fetch("INSERT INTO users (name) VALUES (%s)", "invalid")  # Invalid conditions
    
    @patch('query_handler.QueryHandler.connect')
    def test_execute_non_fetch_runtime_error(self, mock_connect):
        # Set up mock to throw an error
        mock_connect.side_effect = RuntimeError("Connection error")
        
        # Check that the error is propagated
        with self.assertRaises(RuntimeError):
            self.query_handler.execute_non_fetch("INSERT INTO users (name) VALUES (%s)", ("Test User",))


if __name__ == "__main__":
    unittest.main()