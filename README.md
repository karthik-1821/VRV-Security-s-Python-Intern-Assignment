# VRV-Security-s-Python-Intern-Assignment
import csv
from collections import Counter, defaultdict

def parse_log_file(file_path):
    """Parses the log file and extracts relevant information."""
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_login_attempts = defaultdict(int)
    suspicious_ips = {}
    
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) < 9:
                continue
            
            # Extract IP address and endpoint
            ip_address = parts[0]
            endpoint = parts[6]
            status_code = parts[8]
            
            # Count requests per IP and endpoint
            ip_requests[ip_address] += 1
            endpoint_requests[endpoint] += 1
            
            # Detect failed login attempts
            if status_code == '401' or 'Invalid credentials' in line:
                failed_login_attempts[ip_address] += 1
    
    # Flag IPs with suspicious activity
    threshold = 10
    for ip, count in failed_login_attempts.items():
        if count > threshold:
            suspicious_ips[ip] = count
    
    return ip_requests, endpoint_requests, suspicious_ips

def save_to_csv(ip_requests, endpoint_requests, suspicious_ips, output_file):
    """Saves the analysis results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        
        # Write Requests per IP section
        csvwriter.writerow(["Requests per IP"])
        csvwriter.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            csvwriter.writerow([ip, count])
        csvwriter.writerow([])
        
        # Write Most Accessed Endpoint section
        csvwriter.writerow(["Most Accessed Endpoint"])
        most_accessed_endpoint = max(endpoint_requests, key=endpoint_requests.get)
        csvwriter.writerow(["Endpoint", "Access Count"])
        csvwriter.writerow([most_accessed_endpoint, endpoint_requests[most_accessed_endpoint]])
        csvwriter.writerow([])
        
        # Write Suspicious Activity section
        csvwriter.writerow(["Suspicious Activity"])
        csvwriter.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            csvwriter.writerow([ip, count])

def display_results(ip_requests, endpoint_requests, suspicious_ips):
    """Displays the results in a clear format."""
    print("Requests per IP:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_requests.items():
        print(f"{ip:<20} {count:<15}")
    print("\n")
    
    most_accessed_endpoint = max(endpoint_requests, key=endpoint_requests.get)
    print("Most Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {endpoint_requests[most_accessed_endpoint]} times)\n")
    
    if suspicious_ips:
        print("Suspicious Activity Detected:")
        print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<20}")
    else:
        print("No suspicious activity detected.")
    print("\n")

if __name__ == "__main__":
    # Define file paths
    log_file_path = "sample.log"
    output_csv_file = "log_analysis_results.csv"
    
    # Process the log file
    ip_requests, endpoint_requests, suspicious_ips = parse_log_file(log_file_path)
    
    # Display results
    display_results(ip_requests, endpoint_requests, suspicious_ips)
    
    # Save results to CSV
    save_to_csv(ip_requests, endpoint_requests, suspicious_ips, output_csv_file)
    print(f"Results have been saved to {output_csv_file}.")
