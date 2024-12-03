import re
import csv
from collections import Counter, defaultdict

# File names
LOG_FILE = "python/sample.log"
OUTPUT_CSV = "log_analysis_results.csv"

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10


def parse_log_file(log_file):
    """Parses the log file and extracts IPs, endpoints, and failed login attempts."""
    ip_requests = Counter()
    endpoint_access = Counter()
    failed_logins = defaultdict(int)

    # Regular expressions for extracting data
    ip_regex = r"(\d{1,3}(?:\.\d{1,3}){3})"
    endpoint_regex = r"\"(?:GET|POST|PUT|DELETE) (/[\w/]+)"
    failed_login_regex = r"401|Invalid credentials"

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(ip_regex, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(endpoint_regex, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access[endpoint] += 1

            # Check for failed login attempts
            if re.search(failed_login_regex, line):
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_access, failed_logins


def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_csv):
    """Saves the analysis results to a CSV file in the desired format."""
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])
        writer.writerow([])

        # Write Most Accessed Endpoint
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity Detected:"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def main():
    # Parse the log file
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)

    # Sort IP requests by count
    sorted_ip_requests = ip_requests.most_common()

    # Find the most frequently accessed endpoint
    most_accessed_endpoint = endpoint_access.most_common(1)[0]

    # Detect suspicious activity
    suspicious_activity = {
        ip: count for ip, count in failed_logins.items() if count > 0
    }

    # Print Results
    print("Requests per IP")
    print("IP Address,Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip},{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address,Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip},{count}")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, OUTPUT_CSV)
    print(f"\nResults saved to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
