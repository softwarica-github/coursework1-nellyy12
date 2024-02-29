import unittest
from unittest.mock import patch, MagicMock
from io import StringIO
from main import *

class TestNetworkScanner(unittest.TestCase):
    def test_PortScanner(self):
        # Test PortScanner initialization
        port_scanner = PortScanner("127.0.0.1", 1, 100)
        self.assertEqual(port_scanner.target_ip, "127.0.0.1")
        self.assertEqual(port_scanner.start_port, 1)
        self.assertEqual(port_scanner.end_port, 100)

        # Test scan_ports method
        open_ports = port_scanner.scan_ports()
        self.assertIsInstance(open_ports, list)

    def test_ServiceDetector(self):
        # Mocking the open ports list
        open_ports = [80, 443]

        # Test ServiceDetector initialization
        service_detector = ServiceDetector("127.0.0.1", open_ports)
        self.assertEqual(service_detector.target_ip, "127.0.0.1")
        self.assertEqual(service_detector.open_ports, open_ports)

        # Mocking the service information retrieval
        with patch("socket.socket") as mock_socket:
            # Mocking __enter__ method to return another mock object
            mock_socket_instance = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_socket_instance
            mock_socket_instance.recv.return_value.decode.return_value = "HTTP"

            # Test the get_service_info method
            service_info = service_detector.get_service_info(80)
            self.assertEqual(service_info, "HTTP")
        
    def test_BannerGrabber(self):
        # Test BannerGrabber initialization
        banner_grabber = BannerGrabber("127.0.0.1", 80)
        self.assertEqual(banner_grabber.target_ip, "127.0.0.1")
        self.assertEqual(banner_grabber.target_port, 80)

        # Mocking the banner retrieval
        with patch("socket.socket") as mock_socket:
            # Mocking __enter__ method to return another mock object
            mock_socket_instance = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_socket_instance
            mock_socket_instance.recv.return_value.decode.return_value = "Welcome to the server"

            # Test the grab_banner method
            banner = banner_grabber.grab_banner()
            self.assertEqual(banner, "Welcome to the server")
    
    def test_WhoisLookup(self):
        # Test WhoisLookup initialization
        whois_lookup = WhoisLookup("127.0.0.1")
        self.assertEqual(whois_lookup.target_ip, "127.0.0.1")

        # Mocking the WHOIS information retrieval
        with patch("socket.gethostbyaddr") as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("example.com", [], ["127.0.0.1"])
            whois_info = whois_lookup.lookup_whois_info()
            self.assertEqual(whois_info, "('example.com', [], ['127.0.0.1'])")
            
    def test_DNSResolver(self):
        # Test DNSResolver initialization
        dns_resolver = DNSResolver("example.com")
        self.assertEqual(dns_resolver.target_url, "example.com")

        # Mocking the DNS resolution
        with patch("socket.gethostbyname") as mock_gethostbyname:
            mock_gethostbyname.return_value = "93.184.216.34"
            resolved_ip = dns_resolver.resolve_dns()
            self.assertEqual(resolved_ip, "93.184.216.34")
            
if __name__ == "__main__":
    unittest.main()
