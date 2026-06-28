import socket
import sys

# Define our target (We will scan our own computer safely!)
target_host = "127.0.0.1"

#  Define the list of ports we want to scan
ports_to_scan = [21, 22, 80, 135, 443]

print(f"Scanning host: {target_host}")
print("Please wait...")
print("-" * 50)

#  Loop through each port and try to connect
for port in ports_to_scan:
    # Create a fresh digital socket for each knock
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set a tiny timeout so it doesn't hang forever waiting
    s.settimeout(1.0)
    
    # Knock on the door! 
    result = s.connect_ex((target_host, port))
    
    # Check the result (0 means success/open)
    if result == 0:
        print(f"Port {port}: OPEN")
    else:
        print(f"Port {port}: Closed")
        
    # Always close the connection after knocking
    s.close()