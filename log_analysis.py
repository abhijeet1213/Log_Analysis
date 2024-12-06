import re
import csv
from collections import Counter, defaultdict

# Configuration
LOG_FILE = 'sample.log'  # Replace with your log file name
FAILED_LOGIN_THRESHOLD = 10  # Configurable threshold

# Data Structures
ip_request_counts = Counter()
endpoint_counts = Counter()
failed_login_attempts = defaultdict(int)

# Log Parsing Regex
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>\w+) (?P<endpoint>/[^\s]*) HTTP/1.[01]" (?P<status>\d+) .*')

# Read and process the log file
try:
    with open(LOG_FILE, 'r') as log_file:
        for line in log_file:
            match = log_pattern.match(line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = int(match.group('status'))

                # Count requests per IP
                ip_request_counts[ip] += 1

                # Count requests to endpoints
                endpoint_counts[endpoint] += 1

                # Detect suspicious activity (failed login attempts)
                if status == 401:
                    failed_login_attempts[ip] += 1
except FileNotFoundError:
    print(f"Error: File '{LOG_FILE}' not found.")
    exit()

# Process Results
# 1. Sort IP requests
sorted_ip_requests = ip_request_counts.most_common()

# 2. Most frequently accessed endpoint
most_accessed_endpoint, most_accessed_count = endpoint_counts.most_common(1)[0]

# 3. Suspicious activity
suspicious_activity = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

# Output Results
print("\nIP Address Request Count:")
print("IP Address           Request Count")
for ip, count in sorted_ip_requests:
    print(f"{ip:<20}{count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

print("\nSuspicious Activity Detected:")
if suspicious_activity:
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20}{count}")
else:
    print("No suspicious activity detected.")

# Save to CSV
with open('log_analysis_results.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)

    # Write IP request counts
    writer.writerow(['Requests per IP'])
    writer.writerow(['IP Address', 'Request Count'])
    for ip, count in sorted_ip_requests:
        writer.writerow([ip, count])

    # Write most accessed endpoint
    writer.writerow([])
    writer.writerow(['Most Accessed Endpoint'])
    writer.writerow(['Endpoint', 'Access Count'])
    writer.writerow([most_accessed_endpoint, most_accessed_count])

    # Write suspicious activity
    writer.writerow([])
    writer.writerow(['Suspicious Activity'])
    writer.writerow(['IP Address', 'Failed Login Count'])
    for ip, count in suspicious_activity.items():
        writer.writerow([ip, count])

print("\nResults saved to 'log_analysis_results.csv'.")
