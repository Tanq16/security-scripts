import os
import sys
import subprocess
import socket
import ssl
import netifaces

RED = "\033[1;31m"
BLUE = "\033[0;34m"
GREEN = "\033[32m"
RESET = "\033[0m"

def is_apipa(ip_address):
    return ip_address.startswith("169.254.")

interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
try:
    ip_address = subprocess.check_output(['ip', '-4', 'addr', 'show', interface]).decode().split()[1].split('/')[0]

    if is_apipa(ip_address):
        print(f"{RED}The APIPA address {ip_address} is assigned.{RESET}")
        sys.exit()

    print(f"{BLUE}Checking Ping...{RESET}")
    for ping_test in ['1.1.1.1', '8.8.8.8']:
        ping_result = subprocess.run(['ping', '-c', '3', '-W', '1', ping_test], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        dns_loss = float(ping_result.stdout.split(", ")[-2].split("%")[0])
        if dns_loss == 0:
            print(f"{GREEN}Ping for {ping_test} is working with {dns_loss} packet loss.{RESET}")
        else:
            print(f"{RED}Failed to ping {ping_test} with {dns_loss}% packet loss.{RESET}")

    print(f"{BLUE}Checking DNS resolution...{RESET}")
    for domain in ["google.com", "cloudflare.com"]:
        try:
            socket.gethostbyname(domain)
            print(f"{GREEN}DNS resolution for {domain} is working.{RESET}")
        except socket.error:
            print(f"{RED}Failed to resolve DNS for {domain}.{RESET}")

    print(f"{BLUE}Checking TLS connectivity...{RESET}")
    for domain in ["www.google.com", "www.cloudflare.com"]:
        try:
            with socket.create_connection((domain, 443)) as sock:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    print(f"{GREEN}TLS connection to {domain} is working.{RESET}")
        except (socket.gaierror, ConnectionRefusedError, ssl.SSLError, OSError):
            print(f"{RED}Failed to establish TLS connection to {domain}.{RESET}")

except Exception as e:
    print(f"{RED}Error checking connectivity: {e}{RESET}")

