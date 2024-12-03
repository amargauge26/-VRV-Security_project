import re
import csv
from collections import defaultdict


# Function to analyze the log file
def analyze_log(file_path):
    # Create dictionaries to store the data
    ip_request_count = defaultdict(int)
    endpoint_access_count = defaultdict(int)
    failed_logins = defaultdict(int)

    # Open and read the log file
    with open(file_path, 'r') as f:
        for line in f:
            # Regex pattern to match the log format
            match = re.match(r'(?P<ip>[\d\.]+) - - \[.*\] "(?P<method>\S+) (?P<endpoint>\S+) .*" (?P<status>\d+) \d+.*',
                             line)
            failed_login_match = re.match(
                r'(?P<ip>[\d\.]+) - - \[.*\] "POST (?P<endpoint>\S+) .*" 401 \d+ "(?P<error_message>.*)"', line)

            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                ip_request_count[ip] += 1
                endpoint_access_count[endpoint] += 1

            if failed_login_match:
                ip = failed_login_match.group('ip')
                endpoint = failed_login_match.group('endpoint')
                failed_logins[ip] += 1

    # Find the most frequently accessed endpoint
    most_accessed_endpoint = max(endpoint_access_count, key=endpoint_access_count.get)
    most_accessed_count = endpoint_access_count[most_accessed_endpoint]

    # Write the results to a CSV file
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for ip, count in ip_request_count.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})

        writer.writerow({})  # Blank line between sections
        writer.writerow({'IP Address': 'Most Frequently Accessed Endpoint', 'Request Count': most_accessed_endpoint})
        writer.writerow({'IP Address': 'Frequency', 'Request Count': most_accessed_count})

        writer.writerow({})  # Blank line between sections
        writer.writerow({'IP Address': 'Suspicious Activity Detected', 'Request Count': 'Failed Login Attempts'})
        for ip, count in failed_logins.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})

    # Print the summary to the console
    print(f"Requests per IP Address:")
    for ip, count in ip_request_count.items():
        print(f"{ip}: {count}")

    print(f"\nMost Frequently Accessed Endpoint: {most_accessed_endpoint} (Accessed {most_accessed_count} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in failed_logins.items():
        print(f"{ip}: {count} failed login attempts")

    print("\nResults saved to log_analysis_results.csv")


# Path to your log file
file_path = 'C:\\Users\\AMAR9XD\\OneDrive\\Desktop\\log file\\log_cheack\\sample.log'

# Call the function
results = analyze_log(file_path)
