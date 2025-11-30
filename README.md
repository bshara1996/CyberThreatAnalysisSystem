# 🛡️ Cyber Threat Analysis System

A comprehensive Python application for analyzing cyber threats, malware incidents, and suspicious activities. This system processes threat data, validates credentials, analyzes activity logs, and generates insightful reports with visualizations.

## 📋 Overview

This system provides a complete solution for cybersecurity professionals to:
- 🔍 **Process and analyze threat data** from various sources
- 🦠 **Detect malware** and categorize incidents by severity
- 👁️ **Monitor suspicious activities** through activity log analysis
- ✅ **Validate database credentials** with comprehensive validation rules
- 📊 **Generate visualizations and reports** for threat analysis
- 💾 **Store and query threat data** using a MySQL database

## ✨ Features

- 📥 **Automated Threat Processing** - Validates and imports threat data from text files
- 🚫 **IP Blacklist Management** - Updates investigation status for blacklisted IPs
- 🎯 **Top Attacker Identification** - Ranks attacker IPs by frequency
- 📊 **Visual Analytics** - Bar charts, pie charts, and scatter plots for threat patterns
- 🔍 **Suspicious Activity Detection** - Analyzes logs to identify anomalous behavior
- 📋 **Excel Reporting** - Comprehensive malware analysis with multi-sheet reports
- ✅ **Credential Validation** - IPv4 and database credential verification
- 🧪 **Comprehensive Testing** - Full test suite with unittest framework

## 🚀 Installation

### 📋 Prerequisites
- 🐍 Python 3.8+
- 🗄️ MySQL Server 5.7+

### ⚙️ Setup

1. **📦 Install dependencies**
   ```bash
   pip install mysql-connector-python pandas matplotlib openpyxl
   ```

2. **🗄️ Configure MySQL database**
   ```sql
   CREATE DATABASE cyber_threats;
   ```

3. **🔧 Update credentials in `main.py`**
   ```python
   db_params = {
       'host': 'localhost',
       'db_name': 'cyber_threats',
       'username': 'your_username',
       'password': 'your_password'
   }
   ```

## 💻 Usage

### ▶️ Running the Application
```bash
python main.py
```

The application will process threat data, generate visualizations, analyze activity logs, and create Excel reports.

### 🧪 Running Tests
```bash
python -m unittest discover -p "test_*.py"
```

## 📁 Project Structure

```
CyberThreatAnalysisSystem/
├── 🚀 main.py                          # Main application entry point
├── 🗄️ db_adaptor.py                    # MySQL database connection handler
├── 🔗 query_handler.py                 # Database query execution wrapper
├── ✅ credentials_validator.py         # Database credentials validation
├── ⚙️ threat_data_processor.py         # Threat data processing and storage
├── 📊 threat_analyzer.py               # Threat visualization and analysis
├── 📝 activity_log_analyzer.py         # Activity log analysis
├── 🦠 malware_analyzer.py              # Malware analysis and Excel reports
├── 📄 threats.txt                      # Input file with threat data
├── 🚫 blacklist.txt                    # Blacklisted IP addresses
├── 📋 activity_log.txt                 # System activity logs
└── 🧪 test_*.py                        # Unit test files
```

## 📊 Data Formats

All input data files are located in the project root folder.

### 📄 Threats File (`threats.txt`)
```
attack_type,date,attacker_ip,country,duration,data_leaked_mb
DDoS,2025-05-01,192.168.1.100,USA,00:15:30,250
SQL_Injection,2025-05-02,10.0.0.50,China,01:23:45,1500
```

### 🚫 Blacklist File (`blacklist.txt`)
```
192.168.1.100
10.0.0.50
```

## 📤 Generated Outputs

### 📊 Visualizations
- 📊 `attack_types.png` - Attack type distribution
- 🌍 `country_distribution.png` - Attacks by country
- 📉 `duration_vs_data_leaked.png` - Duration vs data leaked
- 🦠 `severity_by_type.png` - Malware severity by type

### 📋 Reports
- 📑 `malware_analysis.xlsx` - Multi-sheet Excel report
- 🔍 `suspicious_activity.txt` - Suspicious activities
- 🌐 `suspicious_ips.txt` - Suspicious IP addresses

## 🗄️ Database Schema

```sql
CREATE TABLE IF NOT EXISTS attacks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_type VARCHAR(50) NOT NULL,
    date DATE NOT NULL,
    attacker_ip VARCHAR(15) NOT NULL,
    country VARCHAR(50) NOT NULL,
    duration_sec INT NOT NULL,
    data_leaked_mb INT NOT NULL,
    is_investigated BOOLEAN DEFAULT FALSE
);
```

## 🛠️ Technologies

- 🐍 **Python 3.8+** - Core programming language
- 🗄️ **MySQL** - Database for threat storage
- 🔌 **mysql-connector-python** - MySQL database driver
- 🐼 **pandas** - Data manipulation and Excel generation
- 📊 **matplotlib** - Data visualization
- 📑 **openpyxl** - Excel file creation
- 🧪 **unittest** - Testing framework

---

⚠️ **Note**: Ensure MySQL server is running before executing the application.

Happy coding! 💻✨


