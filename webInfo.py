import argparse
import socket
import requests
import dns.resolver
from bs4 import BeautifulSoup
import ssl
import json
import re
import time
from urllib.parse import urljoin, urlparse
from pattern import SENSITIVE_PATTERNS
import nmap
import builtwith
import os
import textwrap
from argparse import RawTextHelpFormatter
import pyfiglet


def dns_recon(domain, output_file=None):
    output = []
    print(f"DNS Reconnaissance for {domain}")
    
    def get_asn_info(ip):
        try:
            response = requests.get(f"https://api.hackertarget.com/aslookup/?q={ip}")
            return response.text.strip()
        except:
            return "Unknown"

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        output.append("\n----------DNS Servers----------")
        for ns in ns_records:
            ns_name = ns.target.to_text()
            ns_ip = dns.resolver.resolve(ns_name, 'A')[0].to_text()
            asn_info = get_asn_info(ns_ip)
            output.append(f"\n{ns_name}")
            output.append(f"\t{ns_ip}")
            output.append(asn_info)
    except Exception as e:
        output.append(f"Error retrieving NS records: {e}")

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        output.append("\n----------MX Records----------\n")
        for mx in mx_records:
            mx_name = mx.exchange.to_text()
            mx_ip = dns.resolver.resolve(mx_name, 'A')[0].to_text()
            asn_info = get_asn_info(mx_ip)
            output.append(f"{mx.preference} {mx_name}")
            output.append(f"\t{mx_ip}")
            output.append(asn_info)
    except Exception as e:
        output.append(f"Error retrieving MX records: {e}")

    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        output.append("\n----------TXT Records----------\n")
        for txt in txt_records:
            output.append(txt.to_text())
    except Exception as e:
        output.append(f"Error retrieving TXT records: {e}")

    if output_file:
        with open(output_file, 'a') as f:
            for line in output:
                f.write(line + '\n')
    for line in output:
        print(line)

def port_scan(domain, output_file=None):
    output = []
    print(f"Port Scanning for {domain}")
    common_ports = [80, 443, 21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((domain, port))
        if result == 0:
            output.append(f"Port {port}: Open")
        sock.close()
    
    if output_file:
        with open(output_file, 'a') as f:
            for line in output:
                f.write(line + '\n')
    
    for line in output:
        print(line)

def technologies_used(url, output_file=None):
    output = []
    print(f"Technologies used on {url}")
    
    try:
        technologies = builtwith.parse(url)
    except Exception as e:
        print(f"Error analyzing the URL with builtwith: {e}")
        return
    
    # Format the output
    for tech_type, tech_list in technologies.items():
        output.append(f"{tech_type}: {', '.join(tech_list)}")
    
    if output_file:
        with open(output_file, 'a') as f:
            for line in output:
                f.write(line + '\n')
    
    for line in output:
        print(line)


def subdomain_enum(domain, wordlist, output_file=None):
    output = []
    print(f"Sub-domain Enumeration for {domain}")
    subdomains = []
    with open(wordlist, 'r') as file:
        subdomains = file.read().splitlines()
    
    for subdomain in subdomains:
        try:
            full_domain = f"{subdomain}.{domain}"
            result = dns.resolver.resolve(full_domain, 'A')
            for ipval in result:
                output_line = f'{full_domain} | {ipval.to_text()}'
                output.append(output_line)
                print(output_line)
        except:
            pass

    if output_file:
        with open(output_file, 'a') as f:
            for line in output:
                f.write(line + '\n')
   

def directory_enum(url, wordlist, output_file=None):
    output = []
    print(f"Directory Enumeration for {url}")
    directories = []
    with open(wordlist, 'r') as file:
        directories = file.read().splitlines()
    
    for directory in directories:
        full_url = f"{url}/{directory}"
        response = requests.get(full_url)
        if response.status_code != 404:
            output.append(f"Directory found: {full_url} | Status Code: {response.status_code}")

    if output_file:
        with open(output_file, 'a') as f:
            for line in output:
                f.write(line + '\n')
    
    for line in output:
        print(line)

def list_input_fields_from_file(file, output_file=None):
    output = []
    with open(file, 'r') as urls_file:
        urls = urls_file.read().splitlines()
        for url in urls:
            output.append("-----------------------")
            output.append(f"Listing input fields for {url}\n")
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.content, 'html.parser')
                inputs = soup.find_all('input')
                for input_field in inputs:
                    output.append(f"Input Field: {input_field}")
            except Exception as e:
                output.append(f"Error fetching {url}: {e}")
            output.append("-----------------------")

    if output_file:
        with open(output_file, 'a') as f:
            for line in output:
                f.write(line + '\n')
    
    for line in output:
        print(line)

def list_certificates(domain, output_file=None):
    output = []
    print(f"Listing certificates for {domain}")
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.connect((domain, 443))
    cert = conn.getpeercert()
    output.append(json.dumps(cert, indent=4))

    if output_file:
        with open(output_file, 'a') as f:
            for line in output:
                f.write(line + '\n')

    for line in output:
        print(line)

def read_headers_from_file(header_file):
    headers_list = []
    try:
        with open(header_file, 'r') as file:
            for line in file:
                headers = {}
                line = line.strip().strip('"')
                if line:
                    parts = line.split(': ', 1)
                    if len(parts) == 2:
                        headers[parts[0]] = parts[1]
                    elif len(parts) == 1:
                        headers[parts[0]] = ''
                    headers_list.append(headers)
    except Exception as e:
        print(f"Error reading header file: {e}")
    return headers_list


def perform_403_bypass_tests(url, header_file, output_file=None):
    headers_list = read_headers_from_file(header_file)
    results = {}
    results[url] = {}
    for headers in headers_list:
        status_code = test_url(url, headers)
        if status_code:
            results[url][str(headers)] = status_code
    
    if output_file:
        with open(output_file, 'a') as file:
            file.write(json.dumps(results, indent=4) + '\n')
    
    print(json.dumps(results, indent=4))
    return results

def get_banner(ip_or_url, port=None):
    if not port:
        port = 80

    if "://" in ip_or_url:
        ip_or_url = ip_or_url.split("://")[1]
    
    try:
        # Split the URL to extract the host
        host = ip_or_url.split('/')[0]

        # Create a socket connection
        with socket.create_connection((host, port), timeout=10) as sock:
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())

            # Receive the response
            response = sock.recv(4096).decode()
            
            # Extract headers from the response
            headers = {}
            for line in response.split("\r\n")[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key] = value

            return headers

    except socket.gaierror:
        print(f"Failed to resolve domain: {ip_or_url}")
        return None
    except socket.timeout:
        print(f"Connection to {ip_or_url}:{port} timed out")
        return None
    except Exception as e:
        print(f"Failed to get banner for {ip_or_url}:{port} - {e}")
        return None

def fetch_page(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Failed to fetch {url}: {e}")
        return None

def find_js_files(base_url, js_files=None):
    if js_files is None:
        js_files = set()
    
    html_content = fetch_page(base_url)
    if html_content is None:
        return js_files
    
    soup = BeautifulSoup(html_content, 'lxml')
    
    # Find all JS files linked in script tags
    for script in soup.find_all('script', src=True):
        src = script['src']
        if src.endswith('.js'):
            js_file_url = urljoin(base_url, src)
            if js_file_url not in js_files:
                js_files.add(js_file_url)
                print(f"Found JS file: {js_file_url}")

    # Find all directory links
    directory_links = [urljoin(base_url, a['href']) for a in soup.find_all('a', href=True)]
    directory_links = [link for link in directory_links if link.startswith(base_url)]
    
    # Recursively find JS files in directories
    for link in directory_links:
        if link != base_url:
            find_js_files(link, js_files)
    
    return js_files

def scan_js_file(url):
    content = fetch_page(url)
    if content is None:
        return []
    
    sensitive_info = []
    for pattern in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, content)
        sensitive_info.extend(matches)
    
    return sensitive_info

def scan_js_files_for_sensitive_info(base_url):
    print(f"Scanning {base_url} for JS files...")
    js_files = find_js_files(base_url)
    
    if js_files:
        print("\nScanning JS files for sensitive information...")
        for js_file in js_files:
            sensitive_info = scan_js_file(js_file)
            if sensitive_info:
                print(f"\nSensitive information found in {js_file}:")
                for info in sensitive_info:
                    print(info)
            else:
                print(f"No sensitive information found in {js_file}.")
    else:
        print("No JS files found.")

def scan_for_vulnerabilities(target, output_file=None):
    nm = nmap.PortScanner()
    try:
        print(f"Scanning {target} for vulnerabilities...")
        nm.scan(target, arguments=f'-sV --script=vulscan/vulscan.nse')
        if target in nm.all_hosts():
            scan_results = nm[target]['tcp']
            print_scan_results(scan_results, output_file)
            return scan_results
        else:
            print(f"Scan did not return results for {target}.")
    except Exception as e:
        print(f"An error occurred: {e}")

def print_scan_results(scan_results, output_file=None):
    output = []
    for port in scan_results:
        result = f"Port: {port}\n"
        output.append(result)
        if 'script' in scan_results[port]:
            result = "Script results:\n"
            output.append(result)
            for script in scan_results[port]['script']:
                result = f"{script}: {scan_results[port]['script'][script]}\n"
                output.append(result)
    
    if output_file:
        with open(output_file, 'a') as f:
            for line in output:
                f.write(line)
    
    for line in output:
        print(line)


def scrape_buttons_in_website(url):
    session=requests.Session()
    response = session.get(url)  # send a GET request to the url
    soup = BeautifulSoup(response.content, 'html.parser')  # extract the html content

    data = str(soup.find_all('a'))  # find all <a> tags
    matches = []

    # Extract links from the HTML content
    for match in re.finditer('href="', data):
        start = match.end()
        end = data.find('"', start)
        link = data[start:end]

        if link.startswith('/'):
            link = url + link
        elif not link.startswith('http'):
            link = url + '/' + link

        matches.append(link)

    return matches

def scrape_email_from_website(url, output_file=None):
    matches = scrape_buttons_in_website(url)
    emails = set()
    session=requests.Session()
    # Iterate through the links and scrape emails
    for link in matches:
        try:
            print(f'Scraping {link}')
            response = session.get(link)
            soup = BeautifulSoup(response.content, 'html.parser')
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
            found_emails = re.findall(email_pattern, soup.get_text())
            if found_emails:
                print(f'Found emails: {found_emails}')
            emails.update(found_emails)
        except Exception as e:
            print(f'Error: {e}')
            continue

    if output_file:
        with open(output_file, 'a') as f:
            for email in emails:
                f.write(email + '\n')
    
    return list(emails)

def crawl_for_documents(url, output_file=None):
    print(f"Crawling {url} for documents/files...")
    document_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv']
    found_documents = set()
    
    def find_documents(base_url, visited_urls=None):
        if visited_urls is None:
            visited_urls = set()
        
        html_content = fetch_page(base_url)
        if html_content is None:
            return found_documents
        
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Find all links in the page
        links = [urljoin(base_url, a['href']) for a in soup.find_all('a', href=True)]
        
        for link in links:
            if link in visited_urls:
                continue
            visited_urls.add(link)
            
            if any(link.endswith(ext) for ext in document_extensions):
                found_documents.add(link)
                print(f"Found document: {link}")
            elif link.startswith(base_url):
                find_documents(link, visited_urls)
    
    find_documents(url)
    
    if output_file:
        with open(output_file, 'a') as f:
            for doc in found_documents:
                f.write(doc + '\n')
    
    return list(found_documents)

def print_banner():
    banner = pyfiglet.figlet_format("Swiss Knife")
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Web Information Gathering Tool",
        formatter_class=RawTextHelpFormatter,
        epilog="""\
Argument requirements for each choice:
  1. DNS Recon:                   --domain
  2. Port Scan:                   --domain
  3. Technologies Used:           --url
  4. Sub-domain Enumeration:      --domain, --wordlist
  5. Directory Enumeration:       --url, --wordlist
  6. Listing All Input Fields:    --inputfile
  7. Listing Certificates:        --domain
  8. 403 Bypass Testing:          --url, --headerfile
  9. Web Banner Extraction:       --ip or --url, --port
  10. Scan JS Files:              --url
  11. Vulnerability Scan:         --ip
  12. Email Harvester:            --url
  13. Crawl for Documents/Files:  --url
        """
    )
    parser.add_argument('--domain', type=str, help='The domain to gather information about')
    parser.add_argument('--url', type=str, help='The URL to gather information about')
    parser.add_argument('--wordlist', type=str, help='The wordlist file for sub-domain and directory enumeration')
    parser.add_argument('--inputfile', type=str, help='The file containing URLs to find input fields')
    parser.add_argument('--headerfile', type=str, help='The file containing headers for 403 bypass testing')
    parser.add_argument('--output', type=str, help='The file to save the output')
    parser.add_argument('--ip', type=str, help='IP address to get banner information')
    parser.add_argument('--port', type=int, help='Port to use for banner information')

    args = parser.parse_args()

    menu = """
    Please select an option:
    1. DNS Recon
    2. Port Scan
    3. Technologies Used
    4. Sub-domain Enumeration
    5. Directory Enumeration
    6. Listing All Input Fields
    7. Listing Certificates
    8. 403 Bypass Testing
    9. Web Banner Extraction
    10. Scan JS Files for Sensitive Information
    11. Vulnerability Scan
    12. Email Harvester
    13. Crawl for Documents/Files
    14. Exit
    """

    while True:
        print(menu)
        choice = input("Enter your choice: ")
        if choice == '1':
            if args.domain:
                dns_recon(args.domain, args.output)
            else:
                print("Please provide a domain using --domain option")
        elif choice == '2':
            if args.domain:
                port_scan(args.domain, args.output)
            else:
                print("Please provide a domain using --domain option")
        elif choice == '3':
            if args.url:
                technologies_used(args.url, args.output)
            else:
                print("Please provide a URL using --url option")
        elif choice == '4':
            if args.domain:
                if not args.wordlist:
                    print("Please provide a wordlist for sub-domain enumeration")
                else:
                    subdomain_enum(args.domain, args.wordlist, args.output)
            else:
                print("Please provide a domain using --domain option")
        elif choice == '5':
            if args.url:
                if not args.wordlist:
                    print("Please provide a wordlist for directory enumeration")
                else:
                    directory_enum(args.url, args.wordlist, args.output)
            else:
                print("Please provide a URL using --url option")
        elif choice == '6':
            if args.inputfile:
                list_input_fields_from_file(args.inputfile, args.output)
            else:
                print("Please provide a file containing URLs for input field listing using --inputfile option")
        elif choice == '7':
            if args.domain:
                list_certificates(args.domain, args.output)
            else:
                print("Please provide a domain using --domain option")
        elif choice == '8':
            if args.url and args.headerfile:
                perform_403_bypass_tests(args.url, args.headerfile, args.output)
            else:
                print("Please provide a URL using --url option and a header file using --headerfile option")
        elif choice == '9':
            if args.ip or args.url:
                banner = get_banner(args.ip or args.url, args.port)
                if banner:
                    print(f"Banner for {args.ip or args.url}:{args.port or 80}")
                    for key, value in banner.items():
                        print(f"{key}: {value}")
            else:
                print("Please provide an IP or URL using --ip or --url option")
        elif choice == '10':
            if args.url:
                scan_js_files_for_sensitive_info(args.url)
            else:
                print("Please provide a base URL using --url option")
        elif choice == '11':
            if args.ip:
                scan_for_vulnerabilities(args.ip, args.output)
            else:
                print("Please provide an IP address using --ip option")
        elif choice == '12':
            if args.url:
                emails = scrape_email_from_website(args.url, args.output)
                if emails:
                    print(f"Emails found: {emails}")
                else:
                    print("No emails found.")
            else:
                print("Please provide a URL using --url option")
        elif choice == '13':
            if args.url:
                documents = crawl_for_documents(args.url, args.output)
                if documents:
                    print(f"Documents found: {documents}")
                else:
                    print("No documents found.")
            else:
                print("Please provide a URL using --url option")
        elif choice == '14':
            break
        else:
            print("Invalid choice, please try again")

if __name__ == "__main__":
    main()

