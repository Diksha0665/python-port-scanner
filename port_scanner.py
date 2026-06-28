import socket
from concurrent.futures import ThreadPoolExecutor

# Target settings
target_host = "127.0.0.1"

# A localized vulnerability database dictionary
VULN_DB = {
    21: {"service": "FTP", "risk": "High", "desc": "Cleartext authentication. Credentials can be intercepted easily.", "fix": "Disable FTP and migrate to SFTP (SSH File Transfer Protocol)."},
    22: {"service": "SSH", "risk": "Medium", "desc": "Secure Shell access. Vulnerable to brute-force credential stuffing if misconfigured.", "fix": "Disable root login, enforce key-based authentication, and change default port 22."},
    23: {"service": "Telnet", "risk": "Critical", "desc": "All traffic, including passwords, is sent unencrypted over the wire.", "fix": "Immediately disable Telnet service. Replace with SSH completely."},
    80: {"service": "HTTP", "risk": "Low/Medium", "desc": "Unencrypted web server traffic. Susceptible to packet sniffing and MITM attacks.", "fix": "Deploy SSL/TLS certificates and enforce permanent redirection to HTTPS (Port 443)."},
    135: {"service": "RPC", "risk": "Medium", "desc": "Microsoft RPC Endpoint Mapper. Often targeted for network footprinting and memory leaks.", "fix": "Restrict firewall access to trusted IP ranges only; block public access."},
    443: {"service": "HTTPS", "risk": "Info", "desc": "Secure encrypted web traffic. Generally safe unless running outdated TLS configurations.", "fix": "Ensure outdated protocols like TLS 1.0 and 1.1 are disabled on the server configuration."},
    445: {"service": "SMB", "risk": "High/Critical", "desc": "Microsoft Server Message Block. Used for file sharing, but heavily targeted by ransomware (like WannaCry) if exposed.", "fix": "Ensure it is blocked at the network perimeter firewall and patch Windows completely."}
}

# Function to scan a single port and return the result explicitly to the master engine
def scan_single_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((target_host, port))
        s.close()
        
        if result == 0:
            print(f"[+] Port {port}: OPEN 🚪🔓")
            return port  # Return the port directly to the main thread pool coordinator
    except Exception:
        pass
    return None

# Automation Layer: Generates a professional Markdown Advisory Report
def generate_vulnerability_report(open_ports):
    print("\n[!] Generating Automated Intelligence Report...")
    filename = "vulnerability_report.md"
    
    # FIX: Added encoding="utf-8" so Windows can read and write emojis perfectly!
    with open(filename, "w", encoding="utf-8") as report:
        report.write(f"# Cyber Security Vulnerability Assessment Report\n")
        report.write(f"**Target System:** {target_host}\n")
        report.write(f"**Scan Type:** Multi-Threaded Port Audit\n\n")
        report.write(f"--- \n\n")
        
        if not open_ports:
            report.write("## Summary: No open ports discovered during this audit.\n")
            return
            
        report.write("## 🚨 Discovered Vulnerabilities & Mitigations\n\n")
        
        for port in sorted(open_ports):
            if port in VULN_DB:
                info = VULN_DB[port]
                report.write(f"### 🚪 Port {port} - {info['service']} ({info['risk']} Risk)\n")
                report.write(f"- **Description:** {info['desc']}\n")
                report.write(f"- **Remediation Action:** {info['fix']}\n\n")
            else:
                report.write(f"### 🚪 Port {port} - Unknown Service\n")
                report.write(f"- **Description:** Custom or uncatalogued service running on this port.\n")
                report.write(f"- **Remediation Action:** Audit server processes to identify this service.\n\n")
                
    print(f"[📊] Success! Professional report generated: '{filename}'")

# Master Threading Engine
def run_scanner():
    print(f"--- Launching Intelligent Multi-Threaded Port Scanner on {target_host} ---")
    ports_to_scan = [21, 22, 23, 80, 135, 443, 445, 8080] # Added 445 to target list
    
    actual_open_ports = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scan_single_port, port) for port in ports_to_scan]
        
        for future in futures:
            result = future.result()
            if result is not None:
                actual_open_ports.append(result)
        
    generate_vulnerability_report(actual_open_ports)

if __name__ == "__main__":
    run_scanner()