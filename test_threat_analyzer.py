import unittest
import os
from unittest.mock import patch, MagicMock
from threat_analyzer import ThreatAnalyzer

class TestThreatAnalyzer(unittest.TestCase):
    """
    Unit tests for ThreatAnalyzer class
    """
    
    def setUp(self):
        # Create mock for QueryHandler
        self.mock_db_handler = MagicMock()
        
        # Create an instance of the tested class
        self.analyzer = ThreatAnalyzer(self.mock_db_handler)
    
    def tearDown(self):
        # Delete image files created during tests
        for file in ['attack_types.png', 'country_distribution.png', 'duration_vs_data_leaked.png']:
            if os.path.exists(file):
                os.remove(file)
    
    def test_get_attack_type_counts(self):
        # Define mock result for the query
        mock_results = [
            {"attack_type": "Ransomware", "count": 10},
            {"attack_type": "Phishing", "count": 7},
            {"attack_type": "DDoS", "count": 5}
        ]
        self.mock_db_handler.execute_fetch.return_value = mock_results
        
        # Run the tested function
        result = self.analyzer.get_attack_type_counts()
        
        # Check that execute_fetch was called
        self.mock_db_handler.execute_fetch.assert_called_once()
        
        # Check that the correct result was returned
        expected = {"Ransomware": 10, "Phishing": 7, "DDoS": 5}
        self.assertEqual(result, expected)
    
    def test_get_country_distribution(self):
        # Define mock result for the query
        mock_results = [
            {"country": "USA", "count": 15},
            {"country": "Russia", "count": 12},
            {"country": "China", "count": 8}
        ]
        self.mock_db_handler.execute_fetch.return_value = mock_results
        
        # Run the tested function
        result = self.analyzer.get_country_distribution()
        
        # Check that execute_fetch was called
        self.mock_db_handler.execute_fetch.assert_called_once()
        
        # Check that the correct result was returned
        expected = {"USA": 15, "Russia": 12, "China": 8}
        self.assertEqual(result, expected)
    
    def test_get_duration_vs_data_leaked(self):
        # Define mock result for the query
        mock_results = [
            {"duration_sec": 3600, "data_leaked_mb": 500},
            {"duration_sec": 7200, "data_leaked_mb": 1000},
            {"duration_sec": 1800, "data_leaked_mb": 250}
        ]
        self.mock_db_handler.execute_fetch.return_value = mock_results
        
        # Run the tested function
        result = self.analyzer.get_duration_vs_data_leaked()
        
        # Check that execute_fetch was called
        self.mock_db_handler.execute_fetch.assert_called_once()
        
        # Check that the correct result was returned
        expected = [(3600, 500), (7200, 1000), (1800, 250)]
        self.assertEqual(result, expected)
    
    @patch('threat_analyzer.plt')
    def test_plot_attack_types(self, mock_plt):
        # Define mock for get_attack_type_counts
        self.analyzer.get_attack_type_counts = MagicMock(return_value={"Ransomware": 10, "Phishing": 7, "DDoS": 5})
        
        # Run the tested function
        self.analyzer.plot_attack_types("test_attack_types.png")
        
        # Check that the correct functions were called
        self.analyzer.get_attack_type_counts.assert_called_once()
        mock_plt.figure.assert_called_once()
        mock_plt.bar.assert_called_once()
        mock_plt.title.assert_called_once()
        mock_plt.xlabel.assert_called_once()
        mock_plt.ylabel.assert_called_once()
        mock_plt.xticks.assert_called_once()
        mock_plt.tight_layout.assert_called_once()
        mock_plt.savefig.assert_called_once_with("test_attack_types.png")
        mock_plt.close.assert_called_once()
    
    @patch('threat_analyzer.plt')
    def test_plot_country_distribution(self, mock_plt):
        # Define mock for get_country_distribution
        self.analyzer.get_country_distribution = MagicMock(return_value={"USA": 15, "Russia": 12, "China": 8})
        
        # Run the tested function
        self.analyzer.plot_country_distribution("test_country_distribution.png")
        
        # Check that the correct functions were called
        self.analyzer.get_country_distribution.assert_called_once()
        mock_plt.figure.assert_called_once()
        mock_plt.pie.assert_called_once()
        mock_plt.title.assert_called_once()
        mock_plt.axis.assert_called_once_with('equal')
        mock_plt.tight_layout.assert_called_once()
        mock_plt.savefig.assert_called_once_with("test_country_distribution.png")
        mock_plt.close.assert_called_once()
    
    @patch('threat_analyzer.plt')
    def test_plot_duration_vs_data_leaked(self, mock_plt):
        # Define mock for get_duration_vs_data_leaked
        self.analyzer.get_duration_vs_data_leaked = MagicMock(return_value=[(3600, 500), (7200, 1000), (1800, 250)])
        
        # Run the tested function
        self.analyzer.plot_duration_vs_data_leaked("test_duration_vs_data_leaked.png")
        
        # Check that the correct functions were called
        self.analyzer.get_duration_vs_data_leaked.assert_called_once()
        mock_plt.figure.assert_called_once()
        mock_plt.scatter.assert_called_once()
        mock_plt.title.assert_called_once()
        mock_plt.xlabel.assert_called_once()
        mock_plt.ylabel.assert_called_once()
        mock_plt.grid.assert_called_once()
        mock_plt.tight_layout.assert_called_once()
        mock_plt.savefig.assert_called_once_with("test_duration_vs_data_leaked.png")
        mock_plt.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()