from typing import Final

from query_handler import QueryHandler
from threat_data_processor import ThreatDataProcessor
from threat_analyzer import ThreatAnalyzer
from activity_log_analyzer import ActivityLogAnalyzer
from malware_analyzer import MalwareAnalyzer

THREATS_FILE: Final = "threats.txt"
BLACKLIST_FILE: Final = "blacklist.txt"
LOG_FILE: Final = "activity_log.txt"


def main():
    """
    Main function to run the cyber threat analysis project
    """
    print("Starting Cyber Threat Analysis Project...\n")

    # Database connection parameters
    db_params = {
        'host': 'localhost',
        'db_name': 'cyber_threats',
        'username': 'root',
        'password': ''
    }

    try:
        # Initialize database handler
        print("Initializing database connection...")
        db_handler = QueryHandler(**db_params)

        # Part 1: Process threats file and update database
        print("\n--- Part 1: Processing Threats Data ---")
        processor = ThreatDataProcessor(db_handler)

        # Create the attacks table
        processor.create_attacks_table()

        # Process threats file
        print(f"Processing threats file: {THREATS_FILE}")
        threats_data = processor.process_threats_file(THREATS_FILE)
        print(f"Found {len(threats_data)} valid threat entries")

        # Insert threats into database
        processor.insert_threats_to_db(threats_data)

        # Get top attacker IPs
        top_ips = processor.get_top_attacker_ips(10)
        print("\nTop 10 Attacker IPs:")
        for ip_data in top_ips:
            print(f"IP: {ip_data['attacker_ip']}, Attack Count: {ip_data['attack_count']}")

        # Update investigation status based on blacklist
        print(f"\nUpdating investigation status based on blacklist: {BLACKLIST_FILE}")
        processor.update_investigated_status(BLACKLIST_FILE)

        # Part 2: Generate visualizations
        print("\n--- Part 2: Generating Visualizations ---")
        analyzer = ThreatAnalyzer(db_handler)

        # Generate attack types bar chart
        print("Generating attack types bar chart...")
        analyzer.plot_attack_types()

        # Generate country distribution pie chart
        print("Generating country distribution pie chart...")
        analyzer.plot_country_distribution()

        # Generate duration vs data leaked scatter plot
        print("Generating duration vs data leaked scatter plot...")
        analyzer.plot_duration_vs_data_leaked()

        # Part 3: Analyze activity logs
        print("\n--- Part 3: Analyzing Activity Logs ---")
        log_analyzer = ActivityLogAnalyzer(LOG_FILE)

        # Save suspicious activity
        print("Identifying suspicious activities...")
        log_analyzer.save_suspicious_activity()

        # Save suspicious IPs
        print("Extracting suspicious IPs...")
        log_analyzer.save_suspicious_ips()

        # Part 4: Generate Excel report for malware analysis
        print("\n--- Part 4: Generating Malware Analysis Excel Report ---")
        malware_analyzer = MalwareAnalyzer()

        # Generate sample data
        print("Generating sample malware data...")
        malware_analyzer.generate_sample_data()

        # Create Excel report
        print("Creating Excel report...")
        malware_analyzer.create_excel_report()

        # Generate severity by type chart
        print("Generating severity by malware type chart...")
        malware_analyzer.plot_severity_by_type()

        print("\nCyber Threat Analysis Project completed successfully!")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
