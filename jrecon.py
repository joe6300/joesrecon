import os
import subprocess
import argparse

# Required libraries
import nmap
import requests
from bs4 import BeautifulSoup
import nikto
import dirb
import shodan
from theHarvester import harvester
import recon_ng

def nmap_scan(target):
    # Initialize nmap object
    nm = nmap.PortScanner()

    # Run nmap scan with aggressive OS and service detection
    nm.scan(target, arguments='-A')

    # Print the output
    print(nm.scaninfo())
    print(nm.all_hosts())
    print(nm.csv())

def nikto_scan(target):
    # Initialize nikto object
    scanner = nikto.NiktoScan()

    # Run nikto scan
    scanner.run(target)

def dirb_scan(target):
    # Initialize dirb object
    scanner = dirb.Dirb()

    # Run dirb scan
    scanner.run(target, wordlist='/usr/share/dirb/wordlists/common.txt', threaded=True)

def whatweb_scan(target):
    # Send a GET request to the target
    response = requests.get('http://' + target)

    # Parse the HTML content
    soup = BeautifulSoup(response.content, 'html.parser')

    # Print the title tag
    print(soup.title.string)

def recon_ng_scan(target):
    # Initialize recon-ng object
    subprocess.run(['recon-ng', 'recon-ng', 'modules', 'search', 'all'])

    # Run recon-ng scan
    subprocess.run(['recon-ng', 'recon-ng', 'recon', 'hosts', 'add', target])
    subprocess.run(['recon-ng', 'recon-ng', 'modules', 'load', 'discovery/host-osint'])
    subprocess.run(['recon-ng', 'recon-ng', 'options', 'set', 'SOURCE', 'google'])
    subprocess.run(['recon-ng', 'recon-ng', 'options', 'set', 'DOMAIN', target])
    subprocess.run(['recon-ng', 'recon-ng', 'run'])

def shodan_scan(api_key, query):
    # Initialize shodan object
    api = shodan.Shodan(api_key)

    # Run shodan scan
    results = api.search(query)

    # Print the results
    for result in results['matches']:
        print(result['ip_str'])

def theharvester_scan(target):
    # Initialize theharvester object
    harvester.harvester()

    # Run theharvester scan
    subprocess.run(['theHarvester.py', '-d', target, '-b', 'google'])
    subprocess.run(['theHarvester.py', '-d', target, '-b', 'linkedin'])
    subprocess.run(['theHarvester.py', '-d', target, '-b', 'twitter'])
    subprocess.run(['theHarvester.py', '-d', target, '-b', 'bing'])
    subprocess.run(['theHarvester.py', '-d', target, '-b', 'baidu'])

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Automate website recon tools')
    parser.add_argument('target', help='Target website URL')
    parser.add_argument('--api_key', help='Shodan API key')
    parser.add_argument('--query', help='Shodan search query')
    args = parser.parse_args()

    # Run the scans
    nmap_scan(args.target)
    nikto_scan(args.target)
    dirb_scan(args.target)
    whatweb_scan(args.target)
    recon_ng_scan(args.target)
    if args.api_key and args.query:
        shodan_scan(args.api_key, args.query)
    theHarvester_scan(args.target)
    # Run Shodan search
    if args.api_key and args.query:
        shodan_search(args.api_key, args.query)

    # Run TheHarvester
    theharvester_scan(args.target)

    print('Scan complete.')

