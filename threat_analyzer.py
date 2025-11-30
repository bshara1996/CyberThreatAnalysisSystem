import matplotlib.pyplot as plt
from typing import Dict, List, Tuple
from query_handler import QueryHandler

class ThreatAnalyzer:
    """
    Class responsible for analyzing threat data and generating visualizations
    """
    def __init__(self, db_handler: QueryHandler):
        """
        Initialize the ThreatAnalyzer with a database handler
        :param db_handler: QueryHandler instance for database operations
        """
        self.db_handler = db_handler
    
    def get_attack_type_counts(self) -> Dict[str, int]:
        """
        Get the count of attacks by type
        :return: Dictionary mapping attack types to counts
        """
        query = """
        SELECT attack_type, COUNT(*) as count
        FROM attacks
        GROUP BY attack_type
        ORDER BY count DESC
        """
        
        results = self.db_handler.execute_fetch(query, ())
        return {row['attack_type']: row['count'] for row in results}
    
    def get_country_distribution(self) -> Dict[str, int]:
        """
        Get the distribution of attacks by country
        :return: Dictionary mapping countries to attack counts
        """
        query = """
        SELECT country, COUNT(*) as count
        FROM attacks
        GROUP BY country
        ORDER BY count DESC
        """
        
        results = self.db_handler.execute_fetch(query, ())
        return {row['country']: row['count'] for row in results}
    
    def get_duration_vs_data_leaked(self) -> List[Tuple[int, int]]:
        """
        Get the duration of attacks versus the amount of data leaked
        :return: List of tuples containing (duration_sec, data_leaked_mb)
        """
        query = """
        SELECT duration_sec, data_leaked_mb
        FROM attacks
        """
        
        results = self.db_handler.execute_fetch(query, ())
        return [(row['duration_sec'], row['data_leaked_mb']) for row in results]
    
    def plot_attack_types(self, output_file: str = 'attack_types.png') -> None:
        """
        Create a bar chart of attack types
        :param output_file: Path to save the output image
        """
        attack_counts = self.get_attack_type_counts()
        
        plt.figure(figsize=(12, 6))
        plt.bar(attack_counts.keys(), attack_counts.values(), color='skyblue')
        plt.title('Attack Types Distribution')
        plt.xlabel('Attack Type')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close()
        
        print(f"Attack types bar chart saved to {output_file}")
    
    def plot_country_distribution(self, output_file: str = 'country_distribution.png') -> None:
        """
        Create a pie chart of attack distribution by country
        :param output_file: Path to save the output image
        """
        country_counts = self.get_country_distribution()
        
        plt.figure(figsize=(10, 8))
        plt.pie(country_counts.values(), labels=country_counts.keys(), autopct='%1.1f%%', startangle=90)
        plt.title('Attack Distribution by Country')
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close()
        
        print(f"Country distribution pie chart saved to {output_file}")
    
    def plot_duration_vs_data_leaked(self, output_file: str = 'duration_vs_data_leaked.png') -> None:
        """
        Create a scatter plot of attack duration versus data leaked
        :param output_file: Path to save the output image
        """
        data_points = self.get_duration_vs_data_leaked()
        durations = [point[0] for point in data_points]
        data_leaked = [point[1] for point in data_points]
        
        plt.figure(figsize=(10, 6))
        plt.scatter(durations, data_leaked, alpha=0.6)
        plt.title('Attack Duration vs. Data Leaked')
        plt.xlabel('Duration (seconds)')
        plt.ylabel('Data Leaked (MB)')
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close()
        
        print(f"Duration vs. data leaked scatter plot saved to {output_file}")