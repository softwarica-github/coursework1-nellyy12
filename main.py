import socket
from typing import List
from tabulate import tabulate
import requests
import ssl
import concurrent.futures
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext

class PortScanner:
    def __init__(self, target_ip: str, start_port: int, end_port: int):
        self.target_ip = target_ip
        self.start_port = min(start_port, end_port)
        self.end_port = max(start_port, end_port)

    def scan_ports(self) -> List[int]:
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.is_port_open, port) for port in range(self.start_port, self.end_port + 1)]
            open_ports = [future.result() for future in concurrent.futures.as_completed(futures) if future.result()]

        return open_ports

    def is_port_open(self, port: int) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((self.target_ip, port))
            return port if result == 0 else 0

class ServiceDetector:
    def __init__(self, target_ip: str, open_ports: List[int]):
        self.target_ip = target_ip
        self.open_ports = open_ports

    def detect_services(self) -> dict:
        services = {}
        for port in self.open_ports:
            service_info = self.get_service_info(port)
            services[port] = service_info
        return services

    def get_service_info(self, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((self.target_ip, port))
                banner = s.recv(1024).decode('utf-8').strip()
                return banner
        except socket.error:
            return "Unable to retrieve service information"
        except UnicodeDecodeError:
            return "Unable to decode service information"


class BannerGrabber:
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port

    def grab_banner(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((self.target_ip, self.target_port))
                banner = s.recv(1024).decode('utf-8').strip()
                return banner
        except (socket.error, UnicodeDecodeError):
            return "Unable to grab the banner"


class WhoisLookup:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    def lookup_whois_info(self) -> str:
        try:
            whois_info = socket.gethostbyaddr(self.target_ip)
            return str(whois_info)
        except (socket.herror, socket.gaierror):
            return "WHOIS lookup failed"


class DNSResolver:
    def __init__(self, target_url: str):
        self.target_url = target_url

    def resolve_dns(self) -> str:
        try:
            ip_address = socket.gethostbyname(self.target_url)
            return ip_address
        except (socket.herror, socket.gaierror):
            return "DNS resolution failed"


class ServiceAvailabilityChecker:
    def __init__(self, target_ip: str, services: List[str]):
        self.target_ip = target_ip
        self.services = services

    def check_service_availability(self) -> dict:
        availability_results = {}
        for service in self.services:
            is_available = self.is_service_available(service)
            availability_results[service] = is_available
        return availability_results

    def is_service_available(self, service: str) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target_ip, 80))
                return result == 0
        except socket.error:
            return False


class IPReachabilityChecker:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    def check_reachability(self) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target_ip, 80))
                return result == 0
        except socket.error:
            return False


class DNSEnumerator:
    def __init__(self, target_url: str):
        self.target_url = target_url

    def enumerate_dns(self) -> dict:
        dns_info = {}

        # Resolve IP address for the target URL
        dns_resolver = DNSResolver(self.target_url)
        ip_address = dns_resolver.resolve_dns()
        dns_info["IP Address"] = ip_address

        # Perform additional DNS queries if the IP address is available
        if ip_address != "DNS resolution failed":
            try:
                # Identify subdomains and associated IP addresses
                subdomains, _, _ = socket.gethostbyaddr(ip_address)
                dns_info["Subdomains"] = subdomains
            except (socket.herror, socket.gaierror):
                dns_info["Subdomains"] = "Subdomain enumeration failed"

            # Assign a default value to domain_name
            domain_name = "N/A"
            try:
                # Perform a reverse DNS lookup to find the domain name associated with the IP
                domain_name, _, _ = socket.gethostbyaddr(ip_address)
                dns_info["Domain Name"] = domain_name
            except (socket.herror, socket.gaierror):
                dns_info["Domain Name"] = "Reverse DNS lookup failed"

            try:
                # Identify mail servers for the domain
                mail_servers = [mx[1] for mx in
                                socket.getaddrinfo(domain_name, None, socket.AF_INET, socket.SOCK_STREAM)]
                dns_info["Mail Servers"] = mail_servers
            except (socket.herror, socket.gaierror):
                dns_info["Mail Servers"] = "Mail server enumeration failed"

        return dns_info


class IPLocationInfo:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    def get_location_info(self) -> dict:
        try:
            response = requests.get(f"http://ip-api.com/json/{self.target_ip}")
            data = response.json()
            if data["status"] == "fail":
                return {"message": "Unable to fetch location information"}
            else:
                return data
        except requests.exceptions.RequestException:
            return {"message": "Unable to fetch location information"}


class SSLInfoRetriever:
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port

    def retrieve_ssl_info(self) -> dict:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False  # Disable hostname verification
            
            # Use a connected socket for SSL handshake
            with socket.create_connection((self.target_ip, self.target_port)) as s:
                with context.wrap_socket(s, server_hostname=self.target_ip) as ssl_socket:
                    ssl_info = ssl_socket.getpeercert()

                    expiration_date = datetime.strptime(ssl_info['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    remaining_days = (expiration_date - datetime.now()).days

                    return {
                        "Issuer": ssl_info.get('issuer', 'N/A'),
                        "Subject": ssl_info.get('subject', 'N/A'),
                        "Expiration Date": expiration_date.strftime("%Y-%m-%d %H:%M:%S %Z"),
                        "Remaining Days": remaining_days
                    }

        except (socket.error, ssl.SSLError, KeyError) as e:
            return {"message": f"Unable to retrieve SSL/TLS information: {str(e)}"}


class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Enumeration Tool")
        
         # Menu Bar
        menubar = tk.Menu(root)
        root.config(menu=menubar)

        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.exit_application)

        # Entry for user input (IP address or URL)
        self.input_label = ttk.Label(root, text="Enter an IP address or URL:")
        self.input_label.grid(row=0, column=0, padx=10, pady=10)
        self.input_entry = ttk.Entry(root, width=30)
        self.input_entry.grid(row=0, column=1, padx=10, pady=10)

        # Entry for starting port
        self.start_port_label = ttk.Label(root, text="Enter the starting port:")
        self.start_port_label.grid(row=1, column=0, padx=10, pady=10)
        self.start_port_entry = ttk.Entry(root, width=10)
        self.start_port_entry.grid(row=1, column=1, padx=10, pady=10)

        # Entry for ending port
        self.end_port_label = ttk.Label(root, text="Enter the ending port:")
        self.end_port_label.grid(row=2, column=0, padx=10, pady=10)
        self.end_port_entry = ttk.Entry(root, width=10)
        self.end_port_entry.grid(row=2, column=1, padx=10, pady=10)

        # Button to initiate scanning
        self.scan_button = ttk.Button(root, text="Scan", command=self.scan_network)
        self.scan_button.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Button to clear results
        self.clear_button = ttk.Button(root, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=3, column=1, pady=10)

        # Text widget to display results
        self.results_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
        self.results_text.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

    def scan_network(self):
        # Retrieve user inputs
        user_input = self.input_entry.get()
        start_port = int(self.start_port_entry.get())
        end_port = int(self.end_port_entry.get())

        # Initialize the scanner with user inputs
        port_scanner = PortScanner(user_input, start_port, end_port)

        # Port Scanning
        open_ports = port_scanner.scan_ports()
        result_text = f"\nOpen ports: {', '.join(map(str, open_ports))}\n"

        # Service Detection
        service_detector = ServiceDetector(user_input, open_ports)
        services = service_detector.detect_services()
        result_text += f"\nServices:\n"
        table_data = [(port, service_info) for port, service_info in services.items()]
        result_text += tabulate(table_data, headers=["Port", "Service Info"], tablefmt="plain") + "\n"

        # Banner Grabbing (assuming a common service like HTTP on port 80)
        target_port = 80
        banner_grabber = BannerGrabber(user_input, target_port)
        banner = banner_grabber.grab_banner()
        result_text += f"\nBanner for {user_input}:{target_port}:\n{banner}\n"

        # WHOIS Lookup
        whois_lookup = WhoisLookup(user_input)
        whois_info = whois_lookup.lookup_whois_info()
        result_text += f"\nWHOIS information for {user_input}:\n{whois_info}\n"

        # DNS Resolution
        dns_resolver = DNSResolver(user_input)
        resolved_ip = dns_resolver.resolve_dns()
        result_text += f"\nIP address for {user_input}:\n{resolved_ip}\n"

        # Service Availability Check
        common_services = ['http', 'ftp', 'ssh']
        service_checker = ServiceAvailabilityChecker(user_input, common_services)
        service_availability = service_checker.check_service_availability()
        result_text += f"\nService Availability:\n"
        table_data = [(service, 'Available' if is_available else 'Not Available') for service, is_available in
                      service_availability.items()]
        result_text += tabulate(table_data, headers=["Service", "Availability"], tablefmt="plain") + "\n"

        # Check IP reachability
        ip_reachability_checker = IPReachabilityChecker(user_input)
        is_reachable = ip_reachability_checker.check_reachability()
        result_text += f"\nTarget IP Reachability: {'Reachable' if is_reachable else 'Not Reachable'}\n"

        # Fetch IP location information
        ip_location_info = IPLocationInfo(user_input)
        location_info = ip_location_info.get_location_info()
        result_text += f"\nIP Location Information:\n"
        table_data = [(key.capitalize(), value) for key, value in location_info.items() if key != "message"]
        result_text += tabulate(table_data, headers=["Attribute", "Value"], tablefmt="plain") + "\n"

        # DNS Enumeration
        dns_enumerator = DNSEnumerator(user_input)
        dns_info = dns_enumerator.enumerate_dns()
        result_text += f"\nDNS Enumeration:\n"
        table_data = [(key.capitalize(), value) for key, value in dns_info.items()]
        result_text += tabulate(table_data, headers=["Attribute", "Value"], tablefmt="plain") + "\n"

        # SSL/TLS Information (assuming a common secure service like HTTPS on port 443)
        ssl_target_port = 443
        ssl_info_retriever = SSLInfoRetriever(user_input, ssl_target_port)
        ssl_info = ssl_info_retriever.retrieve_ssl_info()
        result_text += f"\nSSL/TLS Information for {user_input}:{ssl_target_port}:\n"
        result_text += tabulate(ssl_info.items(), headers=["Attribute", "Value"], tablefmt="plain") + "\n"

        # Display results in the GUI
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, result_text)

        # Save results to result.txt
        with open("result.txt", "a") as file:
            file.write(f"\n{'=' * 20} Results {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {'=' * 20}\n")
            file.write(result_text)
    
    def clear_results(self):
        # Clear the results in the text widget
        self.results_text.delete(1.0, tk.END)
        
    def exit_application(self):
        # Exit the application
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()
