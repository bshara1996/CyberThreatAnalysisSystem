import os
from typing import List, Dict, Any
from query_handler import QueryHandler


class ThreatDataProcessor:
    """
    Class responsible for processing threat data from files and storing it in the database
    """

    def __init__(self, db_handler: QueryHandler):
        """
        Initialize the ThreatDataProcessor with a database handler
        :param db_handler: QueryHandler instance for database operations
        """
        self.db_handler = db_handler

    def validate_threat_format(self, line: str) -> bool:
        """
        Validate if a line from the threats file has the correct format
        :param line: A line from the threats file
        :return: True if the format is valid, False otherwise
        """
        # Check if the line has 6 fields (attack_type, date, attacker_ip, country, duration, data_leaked_mb)
        fields = line.strip().split(',')
        return len(fields) == 6

    def parse_duration_to_seconds(self, duration: str) -> int:
        """
        Convert duration in format HH:MM:SS to seconds
        :param duration: Duration string in format HH:MM:SS
        :return: Duration in seconds
        """
        hours, minutes, seconds = map(int, duration.split(':'))
        return hours * 3600 + minutes * 60 + seconds

    def process_threats_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Process the threats file and return a list of threat data
        :param file_path: Path to the threats file
        :return: List of dictionaries containing threat data
        """
        threats_data = []

        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                if not self.validate_threat_format(line):
                    print(f"Invalid format in line: {line}")
                    continue

                attack_type, date, attacker_ip, country, duration, data_leaked_mb = line.split(',')

                # Convert duration to seconds
                duration_sec = self.parse_duration_to_seconds(duration)

                threats_data.append({
                    'attack_type': attack_type,
                    'date': date,
                    'attacker_ip': attacker_ip,
                    'country': country,
                    'duration_sec': duration_sec,
                    'data_leaked_mb': int(data_leaked_mb),
                    'is_investigated': False
                })

        return threats_data

    def create_attacks_table(self) -> None:
        """
        Create the attacks table in the database if it doesn't exist
        """
        create_table_query = """
        CREATE TABLE IF NOT EXISTS attacks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            attack_type VARCHAR(50) NOT NULL,
            date DATE NOT NULL,
            attacker_ip VARCHAR(15) NOT NULL,
            country VARCHAR(50) NOT NULL,
            duration_sec INT NOT NULL,
            data_leaked_mb INT NOT NULL,
            is_investigated BOOLEAN DEFAULT FALSE
        )
        """

        self.db_handler.execute_non_fetch(create_table_query, ())
        print("Attacks table created or already exists.")

    def insert_threats_to_db(self, threats_data: List[Dict[str, Any]]) -> None:
        """
        Insert threat data into the database
        :param threats_data: List of dictionaries containing threat data
        """
        insert_query = """
        INSERT INTO attacks (attack_type, date, attacker_ip, country, duration_sec, data_leaked_mb, is_investigated)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        for threat in threats_data:
            self.db_handler.execute_non_fetch(
                insert_query,
                (
                    threat['attack_type'],
                    threat['date'],
                    threat['attacker_ip'],
                    threat['country'],
                    threat['duration_sec'],
                    threat['data_leaked_mb'],
                    threat['is_investigated']
                )
            )

        print(f"Inserted {len(threats_data)} threat records into the database.")

    def get_top_attacker_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get the top attacker IPs based on frequency
        :param limit: Number of top IPs to return
        :return: List of dictionaries containing IP and count
        """
        query = """
        SELECT attacker_ip, COUNT(*) as attack_count
        FROM attacks
        GROUP BY attacker_ip
        ORDER BY attack_count DESC
        LIMIT %s
        """

        results = self.db_handler.execute_fetch(query, (limit,))
        print(f"Retrieved top {limit} attacker IPs.")
        return results

    def update_investigated_status(self, blacklist_file: str) -> None:
        """
        Update the is_investigated status for IPs in the blacklist
        :param blacklist_file: Path to the blacklist file
        """
        # Read blacklisted IPs
        blacklisted_ips = []
        with open(blacklist_file, 'r') as file:
            for line in file:
                ip = line.strip()
                if ip:  # Skip empty lines
                    blacklisted_ips.append(ip)

        # Update database for each IP
        update_query = """
        UPDATE attacks
        SET is_investigated = TRUE
        WHERE attacker_ip = %s
        """

        for ip in blacklisted_ips:
            self.db_handler.execute_non_fetch(update_query, (ip,))

        print(f"Updated investigation status for {len(blacklisted_ips)} IPs.")
