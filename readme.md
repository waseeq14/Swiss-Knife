# Swiss Knife

Swiss Knife is a comprehensive web information gathering tool designed to facilitate penetration testing and reconnaissance tasks. It offers a variety of features for DNS reconnaissance, port scanning, technology detection, subdomain and directory enumeration, and more.

## Features

- **DNS Reconnaissance**: Retrieve DNS records (NS, MX, TXT) for a given domain.
- **Port Scanning**: Scan common ports to check their status (open/closed) on a given domain.
- **Technologies Used**: Identify technologies used on a given URL.
- **Sub-domain Enumeration**: Enumerate subdomains of a given domain using a wordlist.
- **Directory Enumeration**: Enumerate directories on a given URL using a wordlist.
- **Listing All Input Fields**: List all input fields from URLs listed in a file.
- **Listing Certificates**: List SSL certificates for a given domain.
- **403 Bypass Testing**: Perform tests to bypass 403 Forbidden pages using a set of headers.
- **Web Banner Extraction**: Extract banners from web servers.
- **Scan JS Files for Sensitive Information**: Scan JavaScript files for sensitive information.
- **Vulnerability Scan**: Scan for vulnerabilities on a given IP.
- **Email Harvester**: Harvest emails from a given URL.
- **Crawl for Documents/Files**: Crawl a website for documents and files (e.g., PDF, DOCX).

## Requirements

- **Python 3.6+**
- **Required Python packages** (install using `pip install -r requirements.txt`):
  - argparse
  - socket
  - requests
  - dns.resolver
  - beautifulsoup4
  - ssl
  - json
  - re
  - time
  - urlparse
  - pattern
  - nmap
  - builtwith
  - os
  - textwrap
  - pyfiglet

## Installation

Clone the repository:

```sh
git clone https://github.com/yourusername/swiss-knife.git
cd swiss-knife
```

Install the required packages:

```sh
pip install -r requirements.txt
```

## Usage

Run the script using Python and follow the interactive menu to select the desired operation:

```sh
python swiss_knife.py
```

## Command Line Arguments

The following command-line arguments can be used:

- `--domain`: The domain to gather information about.
- `--url`: The URL to gather information about.
- `--wordlist`: The wordlist file for sub-domain and directory enumeration.
- `--inputfile`: The file containing URLs to find input fields.
- `--headerfile`: The file containing headers for 403 bypass testing.
- `--output`: The file to save the output.
- `--ip`: IP address to get banner information.
- `--port`: Port to use for banner information.

## Options

- **DNS Recon**: `--domain`
- **Port Scan**: `--domain`
- **Technologies Used**: `--url`
- **Sub-domain Enumeration**: `--domain`, `--wordlist`
- **Directory Enumeration**: `--url`, `--wordlist`
- **Listing All Input Fields**: `--inputfile`
- **Listing Certificates**: `--domain`
- **403 Bypass Testing**: `--url`, `--headerfile`
- **Web Banner Extraction**: `--ip` or `--url`, `--port`
- **Scan JS Files for Sensitive Information**: `--url`
- **Vulnerability Scan**: `--ip`
- **Email Harvester**: `--url`
- **Crawl for Documents/Files**: `--url`

## Example Usage

```sh
python swiss_knife.py --domain example.com --output results.txt
```

This command will run the script and allow you to perform the desired operation through the interactive menu.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss what you would like to change.

## Note
setup.sh can be used to download and confifure the nmap **vulscan** script which is necassary for vulnerability scanning.