import os

# User inputs
ip = input("Enter IP address: ")
url = input("Enter URL: ")
domain = input("Enter domain: ")

# Determine firewall type
icmp = os.system("ping -c 1 " + ip)  # Check if ICMP is blocked
http = os.system("curl -I " + url)  # Check if HTTP is blocked

# Perform reconnaissance
if icmp == 0 and http == 0:
    # No firewall
    os.system("nmap -sS -sV -T4 " + ip)  # TCP SYN scan
    os.system("nikto -h " + url)  # Web server scanner
    os.system("dirb " + url)  # Directory bruteforcer
    os.system("whatweb " + url)  # Web fingerprinting tool
    os.system("recon-ng -c 'use recon/domains-vulnerabilities' -x 'add domains " + domain + "; run'")  # Exploit search
    os.system("theharvester -d " + domain + " -b all")  # Email harvester
    os.system("shodan search " + domain)  # Shodan search

elif icmp == 0 and http != 0:
    # HTTP blocked
    os.system("nmap -sS -sV -T4 " + ip)  # TCP SYN scan
    os.system("nikto -h " + url)  # Web server scanner
    os.system("dirb " + url)  # Directory bruteforcer
    os.system("theharvester -d " + domain + " -b all")  # Email harvester
    os.system("shodan search " + domain)  # Shodan search

elif icmp != 0 and http == 0:
    # ICMP blocked
    os.system("nmap -Pn -sS -sV -T4 " + ip)  # TCP SYN scan without pinging
    os.system("nikto -h " + url)  # Web server scanner
    os.system("dirb " + url)  # Directory bruteforcer
    os.system("whatweb " + url)  # Web fingerprinting tool
    os.system("recon-ng -c 'use recon/domains-vulnerabilities' -x 'add domains " + domain + "; run'")  # Exploit search
    os.system("theharvester -d " + domain + " -b all")





else:
    
# Both ICMP and HTTP blocked
    # Perform further reconnaissance
    os.system("whois " + ip)  # WHOIS lookup
    os.system("dig " + domain + " ANY")  # DNS lookup
    os.system("host " + url)  # DNS lookup
    os.system("traceroute " + ip)  # Traceroute
    os.system("curl " + url)  # HTTP request
    os.system("curl -k " + url)  # HTTP request with SSL validation disabled

    # Perform vulnerability scanning
    os.system("nmap -Pn -sS -sV --script vuln " + ip)  # Nmap vulnerability scan
    os.system("openvas-cli --target " + ip + " --scan")  # OpenVAS vulnerability scan

    # Perform password cracking
    os.system("hydra -L usernames.txt -P passwords.txt " + ip + " ssh")  # SSH password cracking
    os.system("hydra -L usernames.txt -P passwords.txt " + ip + " ftp")  # FTP password cracking

    # Perform network mapping
    os.system("nmap -sP " + ip + "/24")  # Ping scan of the network
    os.system("nmap -sS -sV -T4 -O " + ip)  # TCP SYN scan with OS detection
print("Reconnaissance and vulnerability scanning complete.")
