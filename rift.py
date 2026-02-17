#!/usr/bin/env python3
"""
Rift - Public file sharing via your public IP
Share files directly from your PC via HTTP link.
"""

import argparse
import http.client
import http.server
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import signal
import socket
import socketserver
import ssl
import struct
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
from abc import ABC, abstractmethod

__version__ = "0.1.0"

logger = logging.getLogger("rift")


def setup_logging(verbose: bool = False):
    """Configure logging for Rift."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


class RateLimiter:
    """Rate limiter to prevent brute-force attacks."""

    def __init__(self, max_attempts=10, window_seconds=60, max_tracked_ips=1000):
        self.attempts = defaultdict(list)
        self.max_attempts = max_attempts
        self.window = timedelta(seconds=window_seconds)
        self.blocked_ips = {}
        self.max_tracked_ips = max_tracked_ips

    def _cleanup_old_entries(self):
        """Remove old entries to prevent unbounded memory growth."""
        now = datetime.now()

        ips_to_remove = []
        for ip, timestamps in self.attempts.items():
            cleaned = [t for t in timestamps if now - t < self.window]
            if cleaned:
                self.attempts[ip] = cleaned
            else:
                ips_to_remove.append(ip)

        for ip in ips_to_remove:
            del self.attempts[ip]

        blocked_to_remove = [
            ip
            for ip, blocked_at in self.blocked_ips.items()
            if now - blocked_at >= timedelta(minutes=5)
        ]
        for ip in blocked_to_remove:
            del self.blocked_ips[ip]

        if len(self.attempts) > self.max_tracked_ips:
            oldest_ips = sorted(
                self.attempts.items(), key=lambda x: max(x[1]) if x[1] else now
            )[: len(self.attempts) - self.max_tracked_ips]
            for ip, _ in oldest_ips:
                del self.attempts[ip]

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

        if len(self.attempts) % 100 == 0:
            self._cleanup_old_entries()

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
            logger.debug("Using existing self-signed certificate")
            return cert_path, key_path

        logger.info("Generating self-signed certificate...")

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

            logger.info("Self-signed certificate generated successfully")
            return cert_path, key_path

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode() if e.stderr else "Unknown error"
            logger.error(f"Failed to generate certificate: {error_msg}")
            raise RuntimeError(f"Failed to generate certificate: {error_msg}")
        except FileNotFoundError:
            logger.error("OpenSSL not found")
            raise RuntimeError(
                "OpenSSL not found. Please install OpenSSL to use HTTPS."
            )
        except OSError as e:
            logger.error(f"OS error during certificate generation: {e}")
            raise RuntimeError(f"Failed to generate certificate: {e}")

    def get_letsencrypt_cert(self, domain: str, email: str) -> Tuple[Path, Path]:
        """Obtain Let's Encrypt certificate using ACME."""
        cert_path = self.cert_dir / f"{domain}.crt"
        key_path = self.cert_dir / f"{domain}.key"

        config_dir = self.cert_dir / "letsencrypt_config"
        work_dir = self.cert_dir / "letsencrypt_work"
        logs_dir = self.cert_dir / "letsencrypt_logs"

        config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        logs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        if cert_path.exists() and key_path.exists():
            if not self._cert_needs_renewal(cert_path):
                print("[SSL] Using existing Let's Encrypt certificate")
                return cert_path, key_path

        print("[SSL] Obtaining Let's Encrypt certificate...")
        print(
            "[SSL] Note: This requires port 80 to be accessible for HTTP-01 challenge"
        )

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
                    "--config-dir",
                    str(config_dir),
                    "--work-dir",
                    str(work_dir),
                    "--logs-dir",
                    str(logs_dir),
                    "--cert-name",
                    domain,
                ],
                check=True,
                capture_output=True,
            )

            le_cert_path = config_dir / "live" / domain / "fullchain.pem"
            le_key_path = config_dir / "live" / domain / "privkey.pem"

            if le_cert_path.exists() and le_key_path.exists():
                shutil.copy2(le_cert_path, cert_path)
                shutil.copy2(le_key_path, key_path)
                os.chmod(key_path, 0o600)
                os.chmod(cert_path, 0o644)

                print("[SSL] Let's Encrypt certificate obtained successfully")
                return cert_path, key_path
            else:
                raise RuntimeError("Certificate files not found after certbot run")

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

        except (
            subprocess.CalledProcessError,
            FileNotFoundError,
            ValueError,
            OSError,
        ) as e:
            logger.debug(f"Could not check certificate expiry: {e}")
            return True


def load_wordlist() -> Optional[list[str]]:
    """Load wordlist from bundled file."""
    candidate_paths = [
        Path(__file__).parent / "wordlist.txt",
        Path(sys.prefix) / "wordlist.txt",
    ]

    for wordlist_path in candidate_paths:
        if not wordlist_path.exists():
            continue

        try:
            with open(wordlist_path, "r") as f:
                words = [line.strip() for line in f if line.strip()]
                if len(words) >= 100:
                    logger.debug(f"Loaded {len(words)} words from wordlist")
                    return words
                else:
                    logger.warning(
                        f"Wordlist too short ({len(words)} words), using fallback"
                    )
        except IOError as e:
            logger.warning(f"Could not read wordlist: {e}, using fallback")
        except Exception as e:
            logger.warning(f"Unexpected error loading wordlist: {e}, using fallback")

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


class PortForwardingMethod(ABC):
    """Abstract base class for port forwarding/tunneling methods."""

    @abstractmethod
    def name(self) -> str:
        """Get the name of this method."""
        pass

    @abstractmethod
    def discover(self) -> bool:
        """Discover if this method is available."""
        pass

    @abstractmethod
    def forward_port(self, port: int, timeout: int, is_port80: bool = False) -> bool:
        """Setup port forwarding/tunnel. Returns True on success."""
        pass

    @abstractmethod
    def get_public_url(self, port: int, secret_code: str, use_ssl: bool) -> str:
        """Get the public URL for accessing the service."""
        pass

    @abstractmethod
    def cleanup(self, port: int, is_port80: bool = False) -> bool:
        """Clean up port forwarding/tunnel. Returns True on success."""
        pass

    def is_tunnel(self) -> bool:
        """Return True if this is a tunnel (not direct port forwarding)."""
        return False


class NATPMPMethod(PortForwardingMethod):
    """NAT-PMP port forwarding."""

    def __init__(self):
        self.gateway = None

    def name(self) -> str:
        return "NAT-PMP"

    def discover(self) -> bool:
        """Discover NAT-PMP gateway."""
        self.gateway = get_default_gateway()
        if not self.gateway:
            logger.debug("NAT-PMP: No default gateway found")
            return False

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            request = struct.pack("!BB", 0, 0)
            sock.sendto(request, (self.gateway, 5351))
            response, _ = sock.recvfrom(1024)
            sock.close()

            if len(response) >= 12:
                version, opcode, result = struct.unpack("!BBH", response[:4])
                if version == 0 and opcode == 128 and result == 0:
                    logger.debug(f"NAT-PMP gateway discovered at {self.gateway}")
                    return True
        except socket.timeout:
            logger.debug("NAT-PMP: Gateway discovery timed out")
        except socket.error as e:
            logger.debug(f"NAT-PMP: Socket error during discovery: {e}")
        except struct.error as e:
            logger.debug(f"NAT-PMP: Invalid response format: {e}")
        except Exception as e:
            logger.warning(f"NAT-PMP: Unexpected error during discovery: {e}")

        return False

    def forward_port(self, port: int, timeout: int, is_port80: bool = False) -> bool:
        """Add port mapping via NAT-PMP."""
        if not self.gateway:
            return False

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            request = struct.pack(
                "!BBHHHI",
                0,
                2,
                0,
                port,
                port,
                timeout,
            )

            sock.sendto(request, (self.gateway, 5351))
            response, _ = sock.recvfrom(1024)
            sock.close()

            if len(response) >= 16:
                version, opcode_resp, result = struct.unpack("!BBH", response[:4])
                if version == 0 and result == 0:
                    return True
        except socket.timeout:
            logger.debug("NAT-PMP: Port forwarding request timed out")
        except socket.error as e:
            logger.debug(f"NAT-PMP: Socket error during port forwarding: {e}")
        except struct.error as e:
            logger.debug(
                f"NAT-PMP: Invalid response format during port forwarding: {e}"
            )
        except OSError as e:
            logger.debug(f"NAT-PMP: OS error during port forwarding: {e}")

        return False

    def get_public_url(self, port: int, secret_code: str, use_ssl: bool) -> str:
        """Get public URL (requires external IP detection)."""
        return None

    def cleanup(self, port: int, is_port80: bool = False) -> bool:
        """Delete port mapping via NAT-PMP."""
        if not self.gateway:
            return False

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            request = struct.pack("!BBHHHI", 0, 2, 0, port, port, 0)

            sock.sendto(request, (self.gateway, 5351))
            response, _ = sock.recvfrom(1024)
            sock.close()

            if len(response) >= 16:
                version, opcode_resp, result = struct.unpack("!BBH", response[:4])
                if version == 0 and result == 0:
                    return True
        except socket.timeout:
            logger.debug("NAT-PMP: Cleanup request timed out")
        except socket.error as e:
            logger.debug(f"NAT-PMP: Socket error during cleanup: {e}")
        except struct.error as e:
            logger.debug(f"NAT-PMP: Invalid response format during cleanup: {e}")
        except OSError as e:
            logger.debug(f"NAT-PMP: OS error during cleanup: {e}")

        return False


class UPnPMethod(PortForwardingMethod):
    """UPnP port forwarding."""

    def __init__(self):
        self.gateway_url = None
        self.service_type = None
        self.control_url = None
        self.local_ip = None

    def name(self) -> str:
        return "UPnP"

    def discover(self) -> bool:
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
                            self.local_ip = get_local_ip()
                            logger.debug(f"UPnP gateway discovered at {location}")
                            return True
                except socket.timeout:
                    logger.debug("UPnP: Discovery timeout")
                    break
        except socket.error as e:
            logger.debug(f"UPnP: Socket error during discovery: {e}")
        except Exception as e:
            logger.warning(f"UPnP: Unexpected error during discovery: {e}")
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
                            logger.debug(
                                f"UPnP: Found service {service_type} at {self.control_url}"
                            )
                            return True

        except ValueError as e:
            logger.debug(f"UPnP: Invalid location format: {e}")
        except http.client.HTTPException as e:
            logger.debug(f"UPnP: HTTP error parsing location: {e}")
        except ET.ParseError as e:
            logger.debug(f"UPnP: XML parse error: {e}")
        except Exception as e:
            logger.debug(f"UPnP: Error parsing location: {e}")

        return False

    def forward_port(self, port: int, timeout: int, is_port80: bool = False) -> bool:
        """Add port mapping via UPnP."""
        if not self.gateway_url or not self.control_url or not self.local_ip:
            return False

        escaped_service_type = xml_escape(str(self.service_type))
        escaped_external_port = xml_escape(str(port))
        escaped_protocol = xml_escape("TCP")
        escaped_internal_port = xml_escape(str(port))
        escaped_internal_ip = xml_escape(str(self.local_ip))
        escaped_lease_duration = xml_escape(str(timeout))

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
<NewLeaseDuration>{escaped_lease_duration}</NewLeaseDuration>
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
                host, port_num = url_parts[0], int(url_parts[1])
            else:
                host, port_num = url_parts[0], 80

            conn = http.client.HTTPConnection(host, port_num, timeout=5)
            conn.request("POST", self.control_url, soap_body, headers)
            response = conn.getresponse()
            conn.close()

            return response.status == 200
        except ValueError as e:
            logger.debug(f"UPnP: Invalid port number in gateway URL: {e}")
            return False
        except http.client.HTTPException as e:
            logger.debug(f"UPnP: HTTP error during port forwarding: {e}")
            return False
        except (socket.error, OSError) as e:
            logger.debug(f"UPnP: Network error during port forwarding: {e}")
            return False

    def get_public_url(self, port: int, secret_code: str, use_ssl: bool) -> str:
        """Get public URL (requires external IP detection)."""
        return None

    def cleanup(self, port: int, is_port80: bool = False) -> bool:
        """Delete port mapping via UPnP."""
        if not self.gateway_url or not self.control_url:
            return False

        escaped_service_type = xml_escape(str(self.service_type))
        escaped_external_port = xml_escape(str(port))
        escaped_protocol = xml_escape("TCP")

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
                host, port_num = url_parts[0], int(url_parts[1])
            else:
                host, port_num = url_parts[0], 80

            conn = http.client.HTTPConnection(host, port_num, timeout=5)
            conn.request("POST", self.control_url, soap_body, headers)
            response = conn.getresponse()
            conn.close()

            return response.status == 200
        except ValueError as e:
            logger.debug(f"UPnP: Invalid port number in gateway URL: {e}")
            return False
        except http.client.HTTPException as e:
            logger.debug(f"UPnP: HTTP error during cleanup: {e}")
            return False
        except (socket.error, OSError) as e:
            logger.debug(f"UPnP: Network error during cleanup: {e}")
            return False


class CloudflaredMethod(PortForwardingMethod):
    """Cloudflared tunnel."""

    def __init__(self):
        self.tunnel_process = None
        self.tunnel_url = None

    def name(self) -> str:
        return "cloudflared"

    def is_tunnel(self) -> bool:
        return True

    def discover(self) -> bool:
        """Check if cloudflared is available."""
        try:
            subprocess.run(
                ["cloudflared", "--version"],
                capture_output=True,
                timeout=2,
                check=False,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def forward_port(self, port: int, timeout: int, is_port80: bool = False) -> bool:
        """Start cloudflared tunnel."""
        if is_port80:
            return True

        try:
            self.tunnel_process = subprocess.Popen(
                ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            import time

            for _ in range(20):
                time.sleep(0.5)
                if self.tunnel_process.stderr:
                    line = self.tunnel_process.stderr.readline()
                    if not line:
                        continue
                    match = re.search(r"https://[\w\-]+\.trycloudflare\.com", line)
                    if match:
                        self.tunnel_url = match.group(0)
                        return True

        except FileNotFoundError:
            logger.debug("cloudflared: cloudflared executable not found")
        except PermissionError as e:
            logger.debug(f"cloudflared: Permission denied starting cloudflared: {e}")
        except OSError as e:
            logger.debug(f"cloudflared: OS error starting cloudflared: {e}")

        return False

    def get_public_url(self, port: int, secret_code: str, use_ssl: bool) -> str:
        """Get public cloudflared URL."""
        if self.tunnel_url:
            return f"{self.tunnel_url}/{secret_code}"
        return None

    def cleanup(self, port: int, is_port80: bool = False) -> bool:
        """Stop cloudflared tunnel."""
        if self.tunnel_process:
            try:
                self.tunnel_process.terminate()
                self.tunnel_process.wait(timeout=5)
                return True
            except subprocess.TimeoutExpired:
                logger.debug("cloudflared: Process did not terminate, forcing kill")
                try:
                    self.tunnel_process.kill()
                    return True
                except (ProcessLookupError, PermissionError, OSError) as e:
                    logger.debug(f"cloudflared: Error killing process: {e}")
            except (ProcessLookupError, PermissionError, OSError) as e:
                logger.debug(f"cloudflared: Error terminating process: {e}")
        return False


class LocalhostRunMethod(PortForwardingMethod):
    """Localhost.run SSH tunnel."""

    def __init__(self):
        self.tunnel_process = None
        self.tunnel_url = None

    def name(self) -> str:
        return "localhost.run"

    def is_tunnel(self) -> bool:
        return True

    def discover(self) -> bool:
        """Check if SSH is available."""
        try:
            subprocess.run(["ssh", "-V"], capture_output=True, timeout=2, check=False)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def forward_port(self, port: int, timeout: int, is_port80: bool = False) -> bool:
        """Start localhost.run SSH tunnel."""
        if is_port80:
            return True

        try:
            import time

            self.tunnel_process = subprocess.Popen(
                [
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ServerAliveInterval=30",
                    "-o",
                    "ServerAliveCountMax=3",
                    "-T",
                    "-R",
                    f"80:localhost:{port}",
                    "localhost.run",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

            for _ in range(30):
                time.sleep(0.5)
                if self.tunnel_process.stdout:
                    line = self.tunnel_process.stdout.readline()
                    if not line:
                        continue

                    if "tunneled with tls termination" in line:
                        match = re.search(
                            r"https://[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z]+", line
                        )
                        if match:
                            self.tunnel_url = match.group(0)
                            logger.debug(f"localhost.run: Got URL {self.tunnel_url}")
                            return True

        except FileNotFoundError:
            logger.debug("localhost.run: ssh executable not found")
        except PermissionError as e:
            logger.debug(f"localhost.run: Permission denied starting SSH: {e}")
        except OSError as e:
            logger.debug(f"localhost.run: OS error starting SSH tunnel: {e}")

        return False

    def get_public_url(self, port: int, secret_code: str, use_ssl: bool) -> str:
        """Get public localhost.run URL."""
        if self.tunnel_url:
            return f"{self.tunnel_url}/{secret_code}"
        return None

    def cleanup(self, port: int, is_port80: bool = False) -> bool:
        """Stop localhost.run SSH tunnel."""
        if self.tunnel_process:
            try:
                self.tunnel_process.terminate()
                self.tunnel_process.wait(timeout=5)
                return True
            except subprocess.TimeoutExpired:
                logger.debug("localhost.run: Process did not terminate, forcing kill")
                try:
                    self.tunnel_process.kill()
                    return True
                except (ProcessLookupError, PermissionError, OSError) as e:
                    logger.debug(f"localhost.run: Error killing process: {e}")
            except (ProcessLookupError, PermissionError, OSError) as e:
                logger.debug(f"localhost.run: Error terminating process: {e}")
        return False


def get_default_gateway() -> Optional[str]:
    """Get the default gateway IP address."""
    try:
        with open("/proc/net/route") as f:
            for line in f:
                fields = line.strip().split()
                if fields[1] == "00000000":
                    gateway_hex = fields[2]
                    gateway_ip = socket.inet_ntoa(
                        struct.pack("<L", int(gateway_hex, 16))
                    )
                    logger.debug(f"Found gateway via /proc/net/route: {gateway_ip}")
                    return gateway_ip
    except FileNotFoundError:
        logger.debug("/proc/net/route not found (not Linux), trying netstat")
    except Exception as e:
        logger.debug(f"Error reading /proc/net/route: {e}")

    try:
        result = subprocess.run(
            ["netstat", "-rn"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        for line in result.stdout.split("\n"):
            if "default" in line.lower() or "0.0.0.0" in line:
                parts = line.split()
                for part in parts:
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", part):
                        if not part.startswith("0.0.0.0"):
                            logger.debug(f"Found gateway via netstat: {part}")
                            return part
    except FileNotFoundError:
        logger.debug("netstat command not found")
    except subprocess.TimeoutExpired:
        logger.debug("netstat command timed out")
    except Exception as e:
        logger.debug(f"Error running netstat: {e}")

    logger.warning("Could not detect default gateway")
    return None


def get_local_ip() -> str:
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except (socket.error, OSError) as e:
        logger.debug(f"Could not determine local IP: {e}")
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


def validate_file_path(file_path: Path) -> Path:
    """Validate file path for security concerns.

    Args:
        file_path: Path to validate

    Returns:
        Resolved absolute path

    Raises:
        ValueError: If path is invalid or unsafe
        FileNotFoundError: If file doesn't exist
    """
    if len(str(file_path)) > 4096:
        raise ValueError("File path too long (maximum 4096 characters)")

    # Resolve to absolute path (follows symlinks)
    try:
        resolved_path = file_path.resolve(strict=True)
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid file path: {e}")

    # Check if file exists and is a regular file
    if not resolved_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not resolved_path.is_file():
        raise ValueError("Path must be a file, not a directory")

    # Prevent sharing of sensitive system files
    sensitive_patterns = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/.ssh/",
        "/proc/",
        "/sys/",
        "/dev/",
    ]

    resolved_str = str(resolved_path)
    for pattern in sensitive_patterns:
        if pattern in resolved_str:
            logger.warning(f"Attempt to share sensitive file: {resolved_path}")
            raise ValueError(
                "Cannot share system files or files in sensitive directories"
            )

    # Check file permissions - must be readable
    if not os.access(resolved_path, os.R_OK):
        raise PermissionError(f"File is not readable: {resolved_path}")

    # Log if the original path was a symlink
    if file_path.is_symlink():
        logger.info(f"Following symlink: {file_path} -> {resolved_path}")

    return resolved_path


class RiftServer:
    """Main Rift server managing HTTP server."""

    def __init__(
        self,
        file_path: str,
        port: int = 8000,
        use_ssl: bool = True,
        strict_ssl: bool = False,
        domain: Optional[str] = None,
        email: Optional[str] = None,
        cert_path: Optional[Path] = None,
        key_path: Optional[Path] = None,
        timeout: int = 600,
        preferred_method: Optional[str] = None,
    ):
        self.file_path = validate_file_path(Path(file_path))

        self.port = port
        self.use_ssl = use_ssl
        self.strict_ssl = strict_ssl
        self.domain = domain
        self.email = email
        self.cert_path = cert_path
        self.key_path = key_path
        self.timeout = timeout
        self.preferred_method = preferred_method
        self.http_server = None
        self.server_thread = None
        self.public_ip = None
        self.active_method: Optional[PortForwardingMethod] = None
        self.port80_method: Optional[PortForwardingMethod] = None
        self.secret_code = generate_secret_code()
        self.download_complete = False
        self.rate_limiter = RateLimiter(max_attempts=10, window_seconds=60)
        self.shutting_down = False

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        """Handle shutdown signals."""
        if self.shutting_down:
            print("\nForce quit...")
            os._exit(1)
        self.shutting_down = True
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
            except urllib.error.URLError as e:
                logger.debug(f"Could not fetch IP from {service}: {e}")
                continue
            except socket.timeout:
                logger.debug(f"Timeout fetching IP from {service}")
                continue
            except OSError as e:
                logger.debug(f"Network error fetching IP from {service}: {e}")
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

            def generate_confirmation_html(self):
                """Generate HTML confirmation page with file details."""
                import html as html_module

                file_size = server_instance.file_path.stat().st_size
                file_name = html_module.escape(server_instance.file_path.name)

                # Format file size
                if file_size < 1024:
                    size_str = f"{file_size} B"
                elif file_size < 1024 * 1024:
                    size_str = f"{file_size / 1024:.1f} KB"
                elif file_size < 1024 * 1024 * 1024:
                    size_str = f"{file_size / (1024 * 1024):.1f} MB"
                else:
                    size_str = f"{file_size / (1024 * 1024 * 1024):.2f} GB"

                # Guess file type
                content_type, _ = mimetypes.guess_type(str(server_instance.file_path))
                file_type = html_module.escape(content_type or "Unknown")

                html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Download File - Rift</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}

        .container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%;
            padding: 40px;
            animation: slideUp 0.4s ease-out;
        }}

        @keyframes slideUp {{
            from {{
                opacity: 0;
                transform: translateY(30px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        .icon {{
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
            font-size: 32px;
        }}

        h1 {{
            font-size: 24px;
            color: #1a202c;
            text-align: center;
            margin-bottom: 12px;
            font-weight: 600;
        }}

        .subtitle {{
            color: #718096;
            text-align: center;
            margin-bottom: 32px;
            font-size: 14px;
        }}

        .file-info {{
            background: #f7fafc;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }}

        .info-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
        }}

        .info-row:not(:last-child) {{
            border-bottom: 1px solid #e2e8f0;
        }}

        .info-label {{
            color: #718096;
            font-size: 14px;
            font-weight: 500;
        }}

        .info-value {{
            color: #1a202c;
            font-size: 14px;
            font-weight: 600;
            text-align: right;
            word-break: break-all;
        }}

        .download-btn {{
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 12px;
            padding: 16px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }}

        .download-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
        }}

        .download-btn:active {{
            transform: translateY(0);
        }}

        .warning {{
            background: #fff5f5;
            border-left: 4px solid #fc8181;
            border-radius: 8px;
            padding: 12px 16px;
            margin-top: 24px;
            font-size: 13px;
            color: #742a2a;
        }}

        .footer {{
            text-align: center;
            margin-top: 24px;
            color: #a0aec0;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">📦</div>
        <h1>File Ready to Download</h1>
        <p class="subtitle">This is a one-time download link. Click below to get your file.</p>

        <div class="file-info">
            <div class="info-row">
                <span class="info-label">File Name</span>
                <span class="info-value">{file_name}</span>
            </div>
            <div class="info-row">
                <span class="info-label">File Size</span>
                <span class="info-value">{size_str}</span>
            </div>
            <div class="info-row">
                <span class="info-label">File Type</span>
                <span class="info-value">{file_type}</span>
            </div>
        </div>

        <button class="download-btn" onclick="window.location.href='{server_instance.secret_code}/download'">
            Download File
        </button>

        <div class="warning">
            ⚠️ This link will expire after the file is downloaded.
        </div>

        <div class="footer">
            Powered by Rift
        </div>
    </div>
</body>
</html>"""
                return html_content

            def do_GET(self):
                """Handle GET request."""
                client_ip = self.client_address[0]

                if not server_instance.rate_limiter.is_allowed(client_ip):
                    self.send_error(429, "Too Many Requests")
                    return

                parsed_path = urllib.parse.urlparse(self.path)
                path = parsed_path.path.strip("/")

                if path == server_instance.secret_code:
                    # Show confirmation page
                    html = self.generate_confirmation_html()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html.encode("utf-8"))))
                    self.end_headers()
                    self.wfile.write(html.encode("utf-8"))
                elif path == f"{server_instance.secret_code}/download":
                    # Serve the actual file
                    self.serve_file()
                else:
                    self.send_error(404, "Not Found")

            def serve_file(self):
                """Serve the actual file and mark download complete."""
                try:
                    file_size = server_instance.file_path.stat().st_size

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

                    with open(server_instance.file_path, "rb") as f:
                        shutil.copyfileobj(f, self.wfile, length=64 * 1024)

                    print("\n[SUCCESS] File downloaded successfully!")
                    print("[INFO] Shutting down server...")

                    server_instance.download_complete = True

                    threading.Thread(target=server_instance.stop, daemon=True).start()

                except FileNotFoundError:
                    logger.error(f"File not found: {server_instance.file_path}")
                    self.send_error(404, "File not available")
                except PermissionError:
                    logger.error(f"Permission denied: {server_instance.file_path}")
                    self.send_error(403, "Access denied")
                except OSError as e:
                    logger.error(f"OS error serving file: {e}")
                    self.send_error(500, "Internal server error")
                except IOError as e:
                    logger.error(f"I/O error serving file: {e}")
                    self.send_error(500, "Internal server error")

        is_tunnel = self.active_method and self.active_method.is_tunnel()
        bind_address = "127.0.0.1" if is_tunnel else get_local_ip()
        self.http_server = socketserver.TCPServer(
            (bind_address, self.port), SecretFileHandler
        )

        if self.use_ssl and not is_tunnel:
            try:
                if self.cert_path and self.key_path:
                    cert_file = self.cert_path
                    key_file = self.key_path
                    print("[SSL] Using provided certificate")
                elif self.domain and self.email:
                    ssl_manager = SSLCertificateManager()
                    cert_file, key_file = ssl_manager.get_letsencrypt_cert(
                        self.domain, self.email
                    )
                elif self.email and self.public_ip:
                    sslip_domain = self.public_ip.replace(".", "-") + ".sslip.io"
                    print(f"[SSL] Using automatic domain: {sslip_domain}")
                    print(
                        "[SSL] Obtaining Let's Encrypt certificate (requires port 80 accessible)..."
                    )
                    ssl_manager = SSLCertificateManager()
                    cert_file, key_file = ssl_manager.get_letsencrypt_cert(
                        sslip_domain, self.email
                    )
                    self.domain = sslip_domain
                else:
                    ssl_manager = SSLCertificateManager()
                    cert_file, key_file = ssl_manager.get_self_signed_cert(
                        self.domain or self.public_ip or "localhost"
                    )
                    print(
                        "[SSL] WARNING: Using self-signed certificate. Browsers will show security warnings."
                    )
                    if not self.email:
                        print(
                            "[SSL] TIP: Use --email to get a trusted certificate automatically via sslip.io"
                        )

                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
                context.minimum_version = ssl.TLSVersion.TLSv1_2

                self.http_server.socket = context.wrap_socket(
                    self.http_server.socket, server_side=True
                )

                protocol = "https"
            except RuntimeError as e:
                if self.strict_ssl:
                    raise
                self.use_ssl = False
                protocol = "http"
                print(f"[SSL] Warning: {e}")
                print(
                    "[SSL] Falling back to HTTP. Install OpenSSL to enable default HTTPS."
                )
                print(
                    "[WARNING] Running without SSL/TLS. All data transmitted in plaintext!"
                )
        else:
            protocol = "http"
            if not is_tunnel:
                print(
                    "[WARNING] Running without SSL/TLS. All data transmitted in plaintext!"
                )

        if is_tunnel:
            print(f"[HTTP] Serving file: {self.file_path.name}")
            print(
                f"[HTTP] Listening on {bind_address}:{self.port} (tunnel provides HTTPS)"
            )
        else:
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

        file_size_mb = self.file_path.stat().st_size / (1024 * 1024)
        if file_size_mb > 10 and self.timeout == 600:
            # Calculate timeout based on 250 KB/s transfer speed with safety margin
            # Formula: 60s base + (file_size_MB * 10s)
            # This assumes: 250 KB/s ≈ 4s per MB, with 2.5x safety margin
            suggested_timeout = int(60 + (file_size_mb * 10))
            suggested_minutes = suggested_timeout // 60

            print(
                f"\n[WARNING] File size is {file_size_mb:.1f} MB, but port timeout is only 10 minutes."
            )
            print(
                "[WARNING] For large files, consider using --timeout to extend the port forwarding duration."
            )
            print(
                f"[WARNING] Suggested timeout: --timeout {suggested_timeout} (≈{suggested_minutes} min, based on 250 KB/s transfer)\n"
            )

        try:
            all_methods = {
                "cloudflared": CloudflaredMethod(),
                "natpmp": NATPMPMethod(),
                "upnp": UPnPMethod(),
                "localhost.run": LocalhostRunMethod(),
            }

            if self.preferred_method:
                if self.preferred_method.lower() not in all_methods:
                    print(
                        f"[ERROR] Unknown method: {self.preferred_method}. Available: {', '.join(all_methods.keys())}"
                    )
                    sys.exit(1)
                methods = [all_methods[self.preferred_method.lower()]]
                print(
                    f"[Port Forwarding] Using specified method: {self.preferred_method}"
                )
            else:
                methods = list(all_methods.values())

            for method in methods:
                print(f"\n[Port Forwarding] Trying {method.name()}...")

                if not method.discover():
                    print(f"[{method.name()}] Not available")
                    continue

                print(f"[{method.name()}] Available! Setting up...")

                if method.forward_port(self.port, self.timeout):
                    print(
                        f"[{method.name()}] Port {self.port} forwarded successfully (timeout: {self.timeout}s)"
                    )
                    self.active_method = method

                    if (
                        self.use_ssl
                        and (self.email or self.domain)
                        and not method.is_tunnel()
                    ):
                        print(
                            f"[{method.name()}] Forwarding port 80 for Let's Encrypt..."
                        )
                        if method.forward_port(80, 300, is_port80=True):
                            print(
                                f"[{method.name()}] Port 80 forwarded successfully (timeout: 5 minutes)"
                            )
                            self.port80_method = method
                        else:
                            print(f"[{method.name()}] Failed to forward port 80")

                    break
                else:
                    print(f"[{method.name()}] Failed to forward port")

            if not self.active_method:
                print("\n[Port Forwarding] All methods failed")
                print("You'll need to manually forward ports in your router")
                if self.use_ssl and (self.email or self.domain):
                    print(f"  - Port {self.port} for file sharing")
                    print("  - Port 80 for Let's Encrypt")
                else:
                    print(f"  - Port {self.port} for file sharing")
                print("\nOr use these methods (in order of priority):")
                print(
                    "  - cloudflared: brew install cloudflared (best security + speed)"
                )
                print("  - NAT-PMP/UPnP: automatic (fastest, but exposes your IP)")
                print(
                    "  - localhost.run: uses SSH (secure but slower, already installed)"
                )

            if not self.active_method or not self.active_method.is_tunnel():
                print("\n[IP] Detecting public IP address...")
                self.public_ip = self._get_public_ip()

                if not self.public_ip:
                    print(
                        "[IP] Warning: Could not detect public IP. You'll need to find it manually."
                    )
                    self.public_ip = "YOUR_PUBLIC_IP"

            self._start_http_server()

            if self.active_method and self.active_method.is_tunnel():
                public_url = self.active_method.get_public_url(
                    self.port, self.secret_code, self.use_ssl
                )
            else:
                protocol = "https" if self.use_ssl else "http"
                host = self.domain if self.domain else self.public_ip
                public_url = f"{protocol}://{host}:{self.port}/{self.secret_code}"

            print("\n" + "=" * 60)
            print("DISPOSABLE LINK (one-time use):")
            print(f"  {public_url}")
            print("=" * 60)

            if self.active_method:
                if self.active_method.is_tunnel():
                    print(f"\nMethod: {self.active_method.name()} (tunnel)")
                else:
                    print(f"\nMethod: {self.active_method.name()}")
                    if self.public_ip and self.public_ip != "YOUR_PUBLIC_IP":
                        print(f"Public IP: {self.public_ip}")
            print(f"Secret code: {self.secret_code}")
            print(f"File: {self.file_path.name}")

            if self.active_method and not self.active_method.is_tunnel():
                if (
                    self.use_ssl
                    and (self.email or self.domain)
                    and not self.port80_method
                ):
                    print(
                        "\nNote: Port 80 forwarding not available (needed for Let's Encrypt)."
                    )
                    print(
                        "      Make sure port 80 is manually forwarded in your router."
                    )

            print("\nWaiting for download... (Press Ctrl+C to cancel)\n")

            while not self.download_complete:
                import time

                time.sleep(0.5)

            import time

            time.sleep(1)
            sys.exit(0)

        except KeyboardInterrupt:
            print("\n\nShutting down Rift...")
            self.stop()
            sys.exit(0)
        except (RuntimeError, OSError, ValueError) as e:
            logger.error(f"Error during operation: {e}")
            print(f"\nError: {e}", file=sys.stderr)
            self.stop()
            sys.exit(1)

    def stop(self):
        """Stop the HTTP server."""
        if self.http_server:
            print("[HTTP] Stopping HTTP server...")
            try:
                if self.server_thread and self.server_thread.is_alive():
                    self.http_server.shutdown()
                self.http_server.server_close()
            except (OSError, RuntimeError) as e:
                logger.debug(f"Error stopping HTTP server: {e}")
            self.http_server = None

        if self.active_method:
            print(f"[{self.active_method.name()}] Cleaning up port {self.port}...")
            try:
                if self.active_method.cleanup(self.port):
                    print(
                        f"[{self.active_method.name()}] Port {self.port} cleaned up successfully"
                    )
                else:
                    print(
                        f"[{self.active_method.name()}] Warning: Could not clean up port {self.port}"
                    )
            except (OSError, RuntimeError) as e:
                logger.debug(f"Error cleaning up port {self.port}: {e}")

        if self.port80_method:
            print(f"[{self.port80_method.name()}] Cleaning up port 80...")
            try:
                if self.port80_method.cleanup(80, is_port80=True):
                    print(
                        f"[{self.port80_method.name()}] Port 80 cleaned up successfully"
                    )
                else:
                    print(
                        f"[{self.port80_method.name()}] Warning: Could not clean up port 80"
                    )
            except (OSError, RuntimeError) as e:
                logger.debug(f"Error cleaning up port 80: {e}")

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
    timeout = args.timeout if args.timeout else 600
    method = args.method if hasattr(args, "method") else None

    if domain and not email:
        print(
            "Error: --email is required when using --domain for Let's Encrypt",
            file=sys.stderr,
        )
        sys.exit(1)

    if (cert_path and not key_path) or (key_path and not cert_path):
        print("Error: Both --cert and --key must be provided together", file=sys.stderr)
        sys.exit(1)

    if email and not use_ssl:
        print(
            "Error: --email requires SSL (remove --no-ssl flag)",
            file=sys.stderr,
        )
        sys.exit(1)

    if timeout < 60:
        print(
            "Error: --timeout must be at least 60 seconds",
            file=sys.stderr,
        )
        sys.exit(1)

    strict_ssl = bool(cert_path or key_path or domain or email)

    server = RiftServer(
        file_path=args.file,
        port=port,
        use_ssl=use_ssl,
        strict_ssl=strict_ssl,
        domain=domain,
        email=email,
        cert_path=cert_path,
        key_path=key_path,
        timeout=timeout,
        preferred_method=method,
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

  Share with automatic trusted certificate (via sslip.io):
    rift share document.pdf --email you@example.com

  Force a specific port forwarding method:
    rift share document.pdf --method cloudflared
    rift share document.pdf --method natpmp

  Share large file with extended timeout:
    rift share largefile.zip --email you@example.com --timeout 3600

  Share with Let's Encrypt on custom domain:
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

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument("--version", action="version", version=f"rift {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    share_parser = subparsers.add_parser("share", help="Share a file")
    share_parser.add_argument("file", help="File to share")
    share_parser.add_argument(
        "-p", "--port", type=int, help="Port to listen on (default: random)"
    )
    share_parser.add_argument(
        "--no-ssl", action="store_true", help="Disable SSL/TLS (not recommended)"
    )
    share_parser.add_argument(
        "--domain", help="Domain name for Let's Encrypt certificate"
    )
    share_parser.add_argument(
        "--email",
        help="Email for Let's Encrypt (enables automatic trusted cert via sslip.io, or required with --domain)",
    )
    share_parser.add_argument("--cert", help="Path to custom SSL certificate file")
    share_parser.add_argument(
        "--key", help="Path to custom SSL key file (required with --cert)"
    )
    share_parser.add_argument(
        "--timeout",
        type=int,
        help="Port forwarding timeout in seconds (default: 600 / 10 minutes, minimum: 60)",
    )
    share_parser.add_argument(
        "--method",
        choices=["cloudflared", "natpmp", "upnp", "localhost.run"],
        help="Force a specific port forwarding method (default: try all in order)",
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

    setup_logging(verbose=getattr(args, "verbose", False))

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
