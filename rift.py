#!/usr/bin/env python3
"""
Rift - Public file sharing via your public IP
Share files directly from your PC via HTTP link.
"""

import argparse
import http.client
import http.server
import json
import mimetypes
import os
import re
import secrets
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict


class RateLimiter:
    """Rate limiter to prevent brute-force attacks."""

    def __init__(self, max_attempts=10, window_seconds=60):
        self.attempts = defaultdict(list)
        self.max_attempts = max_attempts
        self.window = timedelta(seconds=window_seconds)
        self.blocked_ips = {}

    def is_allowed(self, ip_address):
        """Check if IP is allowed to make a request."""
        now = datetime.now()

        if ip_address in self.blocked_ips:
            if now - self.blocked_ips[ip_address] < timedelta(minutes=5):
                return False
            else:
                del self.blocked_ips[ip_address]

        self.attempts[ip_address] = [
            t for t in self.attempts[ip_address] if now - t < self.window
        ]

        if len(self.attempts[ip_address]) >= self.max_attempts:
            self.blocked_ips[ip_address] = now
            return False

        self.attempts[ip_address].append(now)
        return True


class SSLCertificateManager:
    """Manage SSL/TLS certificates."""

    def __init__(self, cert_dir: Optional[Path] = None):
        self.cert_dir = cert_dir or Path.home() / ".config" / "rift" / "certs"
        self.cert_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def get_self_signed_cert(self, domain: str = "localhost") -> Tuple[Path, Path]:
        """Generate or retrieve self-signed certificate."""
        cert_path = self.cert_dir / "selfsigned.crt"
        key_path = self.cert_dir / "selfsigned.key"

        if cert_path.exists() and key_path.exists():
            return cert_path, key_path

        print("[SSL] Generating self-signed certificate...")

        try:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:4096",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                    "-days",
                    "365",
                    "-nodes",
                    "-subj",
                    f"/CN={domain}",
                ],
                check=True,
                capture_output=True,
            )

            os.chmod(key_path, 0o600)
            os.chmod(cert_path, 0o644)

            print("[SSL] Self-signed certificate generated successfully")
            return cert_path, key_path

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to generate certificate: {e.stderr.decode()}")
        except FileNotFoundError:
            raise RuntimeError(
                "OpenSSL not found. Please install OpenSSL to use HTTPS."
            )

    def get_letsencrypt_cert(self, domain: str, email: str) -> Tuple[Path, Path]:
        """Obtain Let's Encrypt certificate using ACME."""
        cert_path = self.cert_dir / f"{domain}.crt"
        key_path = self.cert_dir / f"{domain}.key"
        account_key_path = self.cert_dir / "account.key"

        if cert_path.exists() and key_path.exists():
            if not self._cert_needs_renewal(cert_path):
                print("[SSL] Using existing Let's Encrypt certificate")
                return cert_path, key_path

        print("[SSL] Obtaining Let's Encrypt certificate...")
        print(
            "[SSL] Note: This requires port 80 to be accessible for HTTP-01 challenge"
        )

        if not account_key_path.exists():
            print("[SSL] Generating ACME account key...")
            subprocess.run(
                [
                    "openssl",
                    "genrsa",
                    "-out",
                    str(account_key_path),
                    "4096",
                ],
                check=True,
                capture_output=True,
            )
            os.chmod(account_key_path, 0o600)

        if not key_path.exists():
            print("[SSL] Generating domain private key...")
            subprocess.run(
                [
                    "openssl",
                    "genrsa",
                    "-out",
                    str(key_path),
                    "4096",
                ],
                check=True,
                capture_output=True,
            )
            os.chmod(key_path, 0o600)

        csr_path = self.cert_dir / f"{domain}.csr"
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(key_path),
                "-out",
                str(csr_path),
                "-subj",
                f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )

        try:
            subprocess.run(
                [
                    "certbot",
                    "certonly",
                    "--standalone",
                    "--non-interactive",
                    "--agree-tos",
                    "--email",
                    email,
                    "-d",
                    domain,
                    "--cert-path",
                    str(cert_path),
                    "--key-path",
                    str(key_path),
                ],
                check=True,
                capture_output=True,
            )

            print("[SSL] Let's Encrypt certificate obtained successfully")
            return cert_path, key_path

        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Failed to obtain Let's Encrypt certificate: {e.stderr.decode()}"
            )
        except FileNotFoundError:
            raise RuntimeError(
                "Certbot not found. Please install certbot to use Let's Encrypt."
            )

    def _cert_needs_renewal(self, cert_path: Path) -> bool:
        """Check if certificate needs renewal (< 30 days remaining)."""
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(cert_path),
                    "-noout",
                    "-enddate",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            date_str = result.stdout.strip().replace("notAfter=", "")
            expiry_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (expiry_date - datetime.now()).days

            return days_remaining < 30

        except Exception:
            return True


def load_wordlist() -> Optional[list[str]]:
    """Load wordlist from bundled file."""
    wordlist_path = Path(__file__).parent / "wordlist.txt"

    if wordlist_path.exists():
        try:
            with open(wordlist_path, "r") as f:
                words = [line.strip() for line in f if line.strip()]
                if len(words) >= 100:
                    return words
        except Exception:
            pass

    return None


def generate_pronounceable_word(length: int = 6) -> str:
    """Generate a pronounceable random word using consonant-vowel patterns."""
    consonants = "bcdfghjklmnprstvwxz"
    vowels = "aeiou"

    word = []
    for i in range(length):
        if i % 2 == 0:
            word.append(secrets.choice(consonants))
        else:
            word.append(secrets.choice(vowels))

    return "".join(word)


def generate_secret_code() -> str:
    """Generate a secret code like '4-forest-lunar' or '4-bavute-rofiso'."""
    wordlist = load_wordlist()
    number = secrets.randbelow(10)

    if wordlist:
        word1 = secrets.choice(wordlist)
        word2 = secrets.choice(wordlist)
    else:
        word1 = generate_pronounceable_word(6)
        word2 = generate_pronounceable_word(6)

    return f"{number}-{word1}-{word2}"


class Config:
    """Manage configuration for Rift."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = (
            config_path or Path.home() / ".config" / "rift" / "config.json"
        )
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Load configuration from file."""
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                return json.load(f)
        return {}

    def save(self):
        """Save configuration to file."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=2)
        os.chmod(self.config_path, 0o600)

    def get(self, key: str, default=None):
        """Get configuration value."""
        return self.config.get(key, default)

    def set(self, key: str, value):
        """Set configuration value."""
        self.config[key] = value

    def reset(self):
        """Reset configuration to defaults."""
        self.config = {}
        if self.config_path.exists():
            self.config_path.unlink()


class UPnP:
    """UPnP port forwarding manager."""

    def __init__(self):
        self.gateway_url = None
        self.service_type = None
        self.control_url = None

    def discover_gateway(self) -> bool:
        """Discover UPnP-enabled gateway."""
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            "\r\n"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)

        try:
            sock.sendto(msg.encode(), ("239.255.255.250", 1900))

            while True:
                try:
                    data, addr = sock.recvfrom(1024)
                    response = data.decode("utf-8", errors="ignore")

                    location_match = re.search(
                        r"LOCATION:\s*(.+)", response, re.IGNORECASE
                    )
                    if location_match:
                        location = location_match.group(1).strip()
                        if self._parse_location(location):
                            return True
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            sock.close()

        return False

    def _parse_location(self, location: str) -> bool:
        """Parse gateway location and extract control URL."""
        try:
            if location.startswith("http://"):
                location = location[7:]

            host_port, path = location.split("/", 1)
            path = "/" + path

            if ":" in host_port:
                host, port = host_port.split(":", 1)
                port = int(port)
            else:
                host, port = host_port, 80

            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", path)
            response = conn.getresponse()
            xml_data = response.read().decode("utf-8")
            conn.close()

            root = ET.fromstring(xml_data)

            ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}
            for service in root.findall(".//upnp:service", ns):
                service_type_elem = service.find("upnp:serviceType", ns)
                if service_type_elem is not None:
                    service_type = service_type_elem.text
                    if (
                        "WANIPConnection" in service_type
                        or "WANPPPConnection" in service_type
                    ):
                        control_url_elem = service.find("upnp:controlURL", ns)
                        if control_url_elem is not None:
                            self.gateway_url = f"http://{host}:{port}"
                            self.service_type = service_type
                            self.control_url = control_url_elem.text
                            if not self.control_url.startswith("/"):
                                self.control_url = "/" + self.control_url
                            return True

        except Exception:
            pass

        return False

    def add_port_mapping(
        self,
        external_port: int,
        internal_port: int,
        internal_ip: str,
        protocol: str = "TCP",
    ) -> bool:
        """Add a port mapping via UPnP."""
        if not self.gateway_url or not self.control_url:
            return False

        escaped_service_type = xml_escape(str(self.service_type))
        escaped_external_port = xml_escape(str(external_port))
        escaped_protocol = xml_escape(str(protocol))
        escaped_internal_port = xml_escape(str(internal_port))
        escaped_internal_ip = xml_escape(str(internal_ip))

        soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="{escaped_service_type}">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{escaped_external_port}</NewExternalPort>
<NewProtocol>{escaped_protocol}</NewProtocol>
<NewInternalPort>{escaped_internal_port}</NewInternalPort>
<NewInternalClient>{escaped_internal_ip}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>Rift File Share</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"""

        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{self.service_type}#AddPortMapping"',
        }

        try:
            url_parts = self.gateway_url.replace("http://", "").split(":")
            if len(url_parts) == 2:
                host, port = url_parts[0], int(url_parts[1])
            else:
                host, port = url_parts[0], 80

            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("POST", self.control_url, soap_body, headers)
            response = conn.getresponse()
            conn.close()

            return response.status == 200
        except Exception:
            return False

    def delete_port_mapping(self, external_port: int, protocol: str = "TCP") -> bool:
        """Delete a port mapping via UPnP."""
        if not self.gateway_url or not self.control_url:
            return False

        escaped_service_type = xml_escape(str(self.service_type))
        escaped_external_port = xml_escape(str(external_port))
        escaped_protocol = xml_escape(str(protocol))

        soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:DeletePortMapping xmlns:u="{escaped_service_type}">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{escaped_external_port}</NewExternalPort>
<NewProtocol>{escaped_protocol}</NewProtocol>
</u:DeletePortMapping>
</s:Body>
</s:Envelope>"""

        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{self.service_type}#DeletePortMapping"',
        }

        try:
            url_parts = self.gateway_url.replace("http://", "").split(":")
            if len(url_parts) == 2:
                host, port = url_parts[0], int(url_parts[1])
            else:
                host, port = url_parts[0], 80

            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("POST", self.control_url, soap_body, headers)
            response = conn.getresponse()
            conn.close()

            return response.status == 200
        except Exception:
            return False


def get_local_ip() -> str:
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_random_port() -> int:
    """Get a random available port."""
    for _ in range(10):
        port = secrets.randbelow(2000) + 8000
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("", port))
            sock.close()
            return port
        except OSError:
            continue

    return 8000


class RiftServer:
    """Main Rift server managing HTTP server."""

    def __init__(
        self,
        file_path: str,
        port: int = 8000,
        use_ssl: bool = True,
        domain: Optional[str] = None,
        email: Optional[str] = None,
        cert_path: Optional[Path] = None,
        key_path: Optional[Path] = None,
    ):
        if len(file_path) > 4096:
            raise ValueError("File path too long (maximum 4096 characters)")

        self.file_path = Path(file_path).resolve()

        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")

        if not self.file_path.is_file():
            raise ValueError("Path must be a file, not a directory")

        self.port = port
        self.use_ssl = use_ssl
        self.domain = domain
        self.email = email
        self.cert_path = cert_path
        self.key_path = key_path
        self.http_server = None
        self.server_thread = None
        self.public_ip = None
        self.upnp = None
        self.upnp_mapping_added = False
        self.secret_code = generate_secret_code()
        self.download_complete = False
        self.rate_limiter = RateLimiter(max_attempts=10, window_seconds=60)

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        """Handle shutdown signals."""
        print("\n\nShutting down Rift...")
        self.stop()
        sys.exit(0)

    def _get_public_ip(self) -> Optional[str]:
        """Detect public IP address."""
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
            "https://ipecho.net/plain",
        ]

        for service in services:
            try:
                with urllib.request.urlopen(service, timeout=5) as response:
                    ip = response.read().decode("utf-8").strip()
                    if ip:
                        return ip
            except Exception:
                continue

        return None

    def _create_http_server(self):
        """Create and configure HTTP server."""
        server_instance = self

        class SecretFileHandler(http.server.BaseHTTPRequestHandler):
            """Custom handler that serves file behind secret URL."""

            def log_message(self, format, *args):
                """Log requests."""
                print(f"[ACCESS] {self.address_string()} - {format % args}")

            def do_GET(self):
                """Handle GET request."""
                client_ip = self.client_address[0]

                if not server_instance.rate_limiter.is_allowed(client_ip):
                    self.send_error(429, "Too Many Requests")
                    return

                parsed_path = urllib.parse.urlparse(self.path)
                path = parsed_path.path.strip("/")

                if path == server_instance.secret_code:
                    self.serve_file()
                else:
                    self.send_error(404, "Not Found")

            def serve_file(self):
                """Serve the actual file and mark download complete."""
                try:
                    with open(server_instance.file_path, "rb") as f:
                        file_size = server_instance.file_path.stat().st_size
                        content = f.read()

                    self.send_response(200)

                    content_type, _ = mimetypes.guess_type(
                        str(server_instance.file_path)
                    )
                    if content_type:
                        self.send_header("Content-Type", content_type)
                    else:
                        self.send_header("Content-Type", "application/octet-stream")

                    self.send_header("Content-Length", str(file_size))
                    self.send_header(
                        "Content-Disposition",
                        f'attachment; filename="{server_instance.file_path.name}"',
                    )
                    self.end_headers()
                    self.wfile.write(content)

                    print("\n[SUCCESS] File downloaded successfully!")
                    print("[INFO] Shutting down server...")

                    server_instance.download_complete = True

                    threading.Thread(target=server_instance.stop, daemon=True).start()

                except FileNotFoundError:
                    print(f"[ERROR] File not found: {server_instance.file_path}")
                    self.send_error(404, "File not available")
                except PermissionError:
                    print(f"[ERROR] Permission denied: {server_instance.file_path}")
                    self.send_error(403, "Access denied")
                except Exception as e:
                    print(f"[ERROR] Error serving file: {e}")
                    self.send_error(500, "Internal server error")

        bind_address = get_local_ip()
        self.http_server = socketserver.TCPServer(
            (bind_address, self.port), SecretFileHandler
        )

        if self.use_ssl:
            if self.cert_path and self.key_path:
                cert_file = self.cert_path
                key_file = self.key_path
                print("[SSL] Using provided certificate")
            elif self.domain and self.email:
                ssl_manager = SSLCertificateManager()
                cert_file, key_file = ssl_manager.get_letsencrypt_cert(
                    self.domain, self.email
                )
            else:
                ssl_manager = SSLCertificateManager()
                cert_file, key_file = ssl_manager.get_self_signed_cert(
                    self.domain or self.public_ip or "localhost"
                )
                print(
                    "[SSL] WARNING: Using self-signed certificate. Browsers will show security warnings."
                )

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            self.http_server.socket = context.wrap_socket(
                self.http_server.socket, server_side=True
            )

            protocol = "https"
        else:
            protocol = "http"
            print(
                "[WARNING] Running without SSL/TLS. All data transmitted in plaintext!"
            )

        print(f"[{protocol.upper()}] Serving file: {self.file_path.name}")
        print(f"[{protocol.upper()}] Listening on {bind_address}:{self.port}")

        return self.http_server

    def _start_http_server(self):
        """Start HTTP server in a separate thread."""
        server = self._create_http_server()
        self.server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.server_thread.start()

    def start(self):
        """Start the HTTP server."""
        print("=" * 60)
        print("Rift - Public File Sharing")
        print("=" * 60)

        try:
            print("\n[UPnP] Discovering gateway...")
            self.upnp = UPnP()

            if self.upnp.discover_gateway():
                print("[UPnP] Gateway found! Configuring port forwarding...")
                local_ip = get_local_ip()
                print(f"[UPnP] Local IP: {local_ip}")

                if self.upnp.add_port_mapping(self.port, self.port, local_ip):
                    print(f"[UPnP] Port {self.port} forwarded successfully")
                    self.upnp_mapping_added = True
                else:
                    print("[UPnP] Failed to add port mapping")
                    print("[UPnP] You may need to configure port forwarding manually")
            else:
                print("[UPnP] No UPnP-enabled gateway found")
                print(
                    "[UPnP] You'll need to manually forward port {} in your router".format(
                        self.port
                    )
                )

            print("\n[IP] Detecting public IP address...")
            self.public_ip = self._get_public_ip()

            if not self.public_ip:
                print(
                    "[IP] Warning: Could not detect public IP. You'll need to find it manually."
                )
                self.public_ip = "YOUR_PUBLIC_IP"

            self._start_http_server()

            protocol = "https" if self.use_ssl else "http"
            host = self.domain if self.domain else self.public_ip
            public_url = f"{protocol}://{host}:{self.port}/{self.secret_code}"

            print("\n" + "=" * 60)
            print("DISPOSABLE LINK (one-time use):")
            print(f"  {public_url}")
            print("=" * 60)

            if self.public_ip != "YOUR_PUBLIC_IP":
                print(f"\nYour public IP: {self.public_ip}")
            print(f"Secret code: {self.secret_code}")
            print(f"File: {self.file_path.name}")

            if not self.upnp_mapping_added:
                print("\nNote: UPnP port forwarding not available.")
                print(
                    "      Make sure port {} is manually forwarded in your router.".format(
                        self.port
                    )
                )

            print("\nWaiting for download... (Press Ctrl+C to cancel)\n")

            while not self.download_complete:
                import time

                time.sleep(0.5)

            import time

            time.sleep(1)
            sys.exit(0)

        except Exception as e:
            print(f"\nError: {e}", file=sys.stderr)
            self.stop()
            sys.exit(1)

    def stop(self):
        """Stop the HTTP server."""
        if self.http_server:
            print("[HTTP] Stopping HTTP server...")
            self.http_server.shutdown()
            self.http_server = None

        if self.upnp and self.upnp_mapping_added:
            print("[UPnP] Removing port forwarding...")
            if self.upnp.delete_port_mapping(self.port):
                print("[UPnP] Port mapping removed successfully")
            else:
                print("[UPnP] Warning: Could not remove port mapping")

        print("Rift stopped.")


def cmd_share(args):
    """Handle the 'share' command."""
    config = Config()

    if args.port:
        port = int(args.port)
    elif config.get("port"):
        port = int(config.get("port"))
    else:
        port = get_random_port()
        print(f"[PORT] Using random port: {port}")

    use_ssl = not args.no_ssl
    domain = args.domain
    email = args.email
    cert_path = Path(args.cert) if args.cert else None
    key_path = Path(args.key) if args.key else None

    if domain and not email:
        print(
            "Error: --email is required when using --domain for Let's Encrypt",
            file=sys.stderr,
        )
        sys.exit(1)

    if (cert_path and not key_path) or (key_path and not cert_path):
        print("Error: Both --cert and --key must be provided together", file=sys.stderr)
        sys.exit(1)

    server = RiftServer(
        file_path=args.file,
        port=port,
        use_ssl=use_ssl,
        domain=domain,
        email=email,
        cert_path=cert_path,
        key_path=key_path,
    )

    server.start()


def cmd_config(args):
    """Handle the 'config' command."""
    config = Config()

    if args.action == "set":
        if not args.key or not args.value:
            print("Error: Both key and value are required for 'set'", file=sys.stderr)
            sys.exit(1)

        value = args.value
        if args.key == "port":
            try:
                value = int(value)
            except ValueError:
                print("Error: Port must be a number", file=sys.stderr)
                sys.exit(1)

        config.set(args.key, value)
        config.save()
        print(f"Configuration saved: {args.key} = {value}")

    elif args.action == "get":
        if not args.key:
            print(json.dumps(config.config, indent=2))
        else:
            value = config.get(args.key)
            if value is not None:
                print(f"{args.key} = {value}")
            else:
                print(f"No value set for: {args.key}", file=sys.stderr)

    elif args.action == "list":
        print(json.dumps(config.config, indent=2))

    elif args.action == "reset":
        config.reset()
        print("Configuration reset to defaults")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Rift - Share files via your public IP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Share a file (HTTPS with self-signed cert):
    rift share document.pdf

  Share with Let's Encrypt certificate:
    rift share document.pdf --domain example.com --email you@example.com

  Share with custom certificate:
    rift share document.pdf --cert /path/to/cert.pem --key /path/to/key.pem

  Share without SSL (not recommended):
    rift share document.pdf --no-ssl

  Share on a custom port:
    rift share document.pdf --port 9000

  Configure default port:
    rift config set port 9000

  Reset configuration:
    rift config reset

  List configuration:
    rift config list
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    share_parser = subparsers.add_parser("share", help="Share a file or directory")
    share_parser.add_argument("file", help="File or directory to share")
    share_parser.add_argument(
        "-p", "--port", type=int, help="Port to listen on (default: 8000)"
    )
    share_parser.add_argument(
        "--no-ssl", action="store_true", help="Disable SSL/TLS (not recommended)"
    )
    share_parser.add_argument(
        "--domain", help="Domain name for Let's Encrypt certificate"
    )
    share_parser.add_argument(
        "--email", help="Email for Let's Encrypt certificate (required with --domain)"
    )
    share_parser.add_argument("--cert", help="Path to custom SSL certificate file")
    share_parser.add_argument(
        "--key", help="Path to custom SSL key file (required with --cert)"
    )
    share_parser.set_defaults(func=cmd_share)

    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_parser.add_argument(
        "action", choices=["set", "get", "list", "reset"], help="Configuration action"
    )
    config_parser.add_argument("key", nargs="?", help="Configuration key")
    config_parser.add_argument("value", nargs="?", help="Configuration value")
    config_parser.set_defaults(func=cmd_config)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
