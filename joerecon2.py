import subprocess

# Nmap scan
def nmap_scan(ip):
    command = f"nmap -sV -p- -T4 {ip}"
    results = subprocess.check_output(command, shell=True)
    return results.decode()

# Nikto scan
def nikto_scan(url):
    command = f"nikto -h {url}"
    results = subprocess.check_output(command, shell=True)
    return results.decode()

# Dirbuster scan
def dirbuster_scan(url):
    command = f"java -jar dirbuster.jar -u {url} -e php,html,txt -w wordlists/directory-list-2.3-medium.txt -t 50"
    results = subprocess.check_output(command, shell=True)
    return results.decode()

# WhatWeb scan
def whatweb_scan(url):
    command = f"whatweb {url}"
    results = subprocess.check_output(command, shell=True)
    return results.decode()

# Recon-ng scan
def recon_scan(url):
    command = f"recon-ng -r {url}"
    results = subprocess.check_output(command, shell=True)
    return results.decode()

# Shodan scan
def shodan_scan(ip):
    command = f"shodan host {ip}"
    results = subprocess.check_output(command, shell=True)
    return results.decode()

# TheHarvester scan
def harvester_scan(domain):
    command = f"theHarvester -d {domain} -l 500 -b google"
    results = subprocess.check_output(command, shell=True)
    return results.decode()

# Run the scans
ip = "192.168.1.1"
url = "https://example.com"
domain = "example.com"

print(nmap_scan(ip))
print(nikto_scan(url))
print(dirbuster_scan(url))
print(whatweb_scan(url))
print(recon_scan(url))
print(shodan_scan(ip))
print(harvester_scan(domain))
