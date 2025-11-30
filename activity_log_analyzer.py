from typing import Dict, List, Tuple, Set

class ActivityLogAnalyzer:
    """
    Class responsible for analyzing activity logs and identifying suspicious activities
    """
    def __init__(self, log_file: str):
        """
        Initialize the ActivityLogAnalyzer with a log file path
        :param log_file: Path to the activity log file
        """
        self.log_file = log_file
    
    def parse_log_line(self, line: str) -> Dict[str, str]:
        """
        Parse a log line into its components
        :param line: A line from the activity log
        :return: Dictionary containing the parsed components
        """
        parts = [part.strip() for part in line.split(',')]
        if len(parts) != 4:
            return {}
        
        return {
            'ip': parts[0],
            'timestamp': parts[1],
            'action': parts[2],
            'result': parts[3]
        }
    
    def is_suspicious(self, log_entry: Dict[str, str]) -> bool:
        """
        Determine if a log entry is suspicious
        :param log_entry: Dictionary containing log entry components
        :return: True if the entry is suspicious, False otherwise
        """
        # Check if the result is a failure
        if log_entry.get('result') == 'FAILURE':
            return True
        
        # Additional suspicious patterns could be added here
        return False
    
    def analyze_logs(self) -> Tuple[List[Dict[str, str]], Set[str]]:
        """
        Analyze the activity logs and identify suspicious activities and IPs
        :return: Tuple containing (suspicious_entries, suspicious_ips)
        """
        suspicious_entries = []
        suspicious_ips = set()
        
        with open(self.log_file, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                
                log_entry = self.parse_log_line(line)
                if not log_entry:
                    continue
                
                if self.is_suspicious(log_entry):
                    suspicious_entries.append(log_entry)
                    suspicious_ips.add(log_entry['ip'])
        
        return suspicious_entries, suspicious_ips
    
    def save_suspicious_activity(self, output_file: str = 'suspicious_activity.txt') -> None:
        """
        Save suspicious activity entries to a file
        :param output_file: Path to save the output file
        """
        suspicious_entries, _ = self.analyze_logs()
        
        with open(output_file, 'w') as file:
            for entry in suspicious_entries:
                file.write(f"{entry['ip']}, {entry['timestamp']}, {entry['action']}, {entry['result']}\n")
        
        print(f"Saved {len(suspicious_entries)} suspicious activity entries to {output_file}")
    
    def save_suspicious_ips(self, output_file: str = 'suspicious_ips.txt') -> None:
        """
        Save unique suspicious IPs to a file
        :param output_file: Path to save the output file
        """
        _, suspicious_ips = self.analyze_logs()
        
        with open(output_file, 'w') as file:
            for ip in suspicious_ips:
                file.write(f"{ip}\n")
        
        print(f"Saved {len(suspicious_ips)} unique suspicious IPs to {output_file}")