# -VRV-Security_project

# Log File Analysis

This Python project is designed to parse web server log files, providing insights into user activity, including the number of requests per IP address, the most frequently accessed endpoints, and detecting suspicious activities such as multiple failed login attempts.

## Features:
- **IP Request Count**: Tracks the number of requests made by each IP address.
- **Most Accessed Endpoint**: Identifies the most frequently accessed endpoint in the log file.
- **Suspicious Activity Detection**: Detects and logs failed login attempts (HTTP 401 status) for each IP address.
- **CSV Output**: Saves the analysis results in a structured CSV file for easy viewing and further analysis.
- **Console Output**: Provides a summary of the log analysis in the console, highlighting key findings.

## Technologies Used:
- Python
- Regular Expressions (`re` module)
- CSV handling (`csv` module)

## How to Use:
1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/yourusername/log-file-analysis.git
