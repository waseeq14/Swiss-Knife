import argparse
import socket
import requests
import dns.resolver
from bs4 import BeautifulSoup
import ssl
import json

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
        response = requests.get(url)
    except Exception as e:
        print(f"Error fetching the URL: {e}")
        return
    
    headers = response.headers
    output.append(f"Headers: {headers}")
    
    # Web servers
    if 'server' in headers:
        output.append(f"Web server: {headers['server']}")
    
    # Powered by
    if 'x-powered-by' in headers:
        output.append(f"Powered by: {headers['x-powered-by']}")
    
    # Programming languages and frameworks
    if 'set-cookie' in headers:
        cookies = headers['set-cookie']
        if 'PHPSESSID' in cookies:
            output.append("Programming language: PHP")
        if 'ASP.NET_SessionId' in cookies:
            output.append("Programming language: ASP.NET")
        if 'JSESSIONID' in cookies:
            output.append("Programming language: Java")
        if 'CFID' in cookies or 'CFTOKEN' in cookies:
            output.append("Programming language: ColdFusion")
    
    # CMS detection
    if 'x-drupal-cache' in headers:
        output.append("CMS: Drupal")
    if 'x-generator' in headers and 'WordPress' in headers['x-generator']:
        output.append("CMS: WordPress")
    if 'x-joomla-cache' in headers:
        output.append("CMS: Joomla")
    if 'x-magento-cache' in headers:
        output.append("CMS: Magento")
    
    # Other technologies
    if 'x-powered-by' in headers:
        if 'Express' in headers['x-powered-by']:
            output.append("Framework: Express.js")
        if 'Django' in headers['x-powered-by']:
            output.append("Framework: Django")
        if 'Ruby on Rails' in headers['x-powered-by']:
            output.append("Framework: Ruby on Rails")
        if 'Laravel' in headers['x-powered-by']:
            output.append("Framework: Laravel")
    
    # Frontend frameworks/libraries
    if 'x-react-server' in headers:
        output.append("Frontend framework: React")
    if 'x-vue-server' in headers:
        output.append("Frontend framework: Vue.js")
    
    # Popular cloud services
    if 'via' in headers and 'cloudfront' in headers['via']:
        output.append("CDN: AWS CloudFront")
    if 'x-amz-cf-id' in headers:
        output.append("CDN: AWS CloudFront")
    if 'x-azure-ref' in headers:
        output.append("Cloud service: Azure")
    if 'x-github-request-id' in headers:
        output.append("Hosting: GitHub Pages")
    
    # Additional heuristics based on content
    if 'wp-content' in response.text.lower():
        output.append("CMS: WordPress")
    if 'sites/default/files' in response.text.lower():
        output.append("CMS: Drupal")
    if 'components/com_' in response.text.lower():
        output.append("CMS: Joomla")
    if 'mage-cache' in response.text.lower():
        output.append("CMS: Magento")
    
    if 'nginx' in response.text.lower():
        output.append("Web server: Nginx")
    if 'apache' in response.text.lower():
        output.append("Web server: Apache")
    
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


def main():
    parser = argparse.ArgumentParser(description="Web Information Gathering Tool")
    parser.add_argument('--domain', type=str, help='The domain to gather information about')
    parser.add_argument('--url', type=str, help='The URL to gather information about')
    parser.add_argument('--wordlist', type=str, help='The wordlist file for sub-domain and directory enumeration')
    parser.add_argument('--inputfile', type=str, help='The file containing URLs to find input fields')
    parser.add_argument('--output', type=str, help='The file to save the output')
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
    8. Exit
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
            break
        else:
            print("Invalid choice, please try again")

if __name__ == "__main__":
    main()

