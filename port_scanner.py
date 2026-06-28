import socket
from concurrent.futures import ThreadPoolExecutor

# Target settings - scanning your own local machine safely
target_host = "127.0.0.1"

# Function to knock on a single specific digital door
def scan_single_port(port):
    try:
        # Create a temporary digital communication line
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a short timeout so threads don't hang around waiting
        s.settimeout(1.0)
        
        # Connect_ex returns 0 if the door is OPEN
        result = s.connect_ex((target_host, port))
        
        if result == 0:
            print(f"[+] Port {port}: OPEN 🚪🔓")
        s.close()
    except Exception:
        pass

# Master Threading Engine
def run_threaded_port_scanner():
    print(f"--- Launching Multi-Threaded Port Scanner on {target_host} ---")
    print("Scanning ports 1 through 1024 concurrently. Please wait...\n")
    
    # Generate a massive checklist of the most important system ports (1 to 1024)
    ports_to_scan = list(range(1, 1025))
    
    # Unleash 100 digital worker hands at the exact same millisecond!
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(scan_single_port, ports_to_scan)

# Fire up the machine
if __name__ == "__main__":
    run_threaded_port_scanner()