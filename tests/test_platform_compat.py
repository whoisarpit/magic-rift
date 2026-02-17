"""Tests for cross-platform compatibility of rift.py"""

import platform
import sys
from pathlib import Path
import tempfile
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import rift


class TestWindowsCompatibility:
    """Test Windows-specific functionality"""

    def test_config_directory_creation(self):
        """Test that config directory can be created on Windows"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "rift" / "config.json"
            config = rift.Config(config_path=config_path)
            config.set("test_key", "test_value")
            config.save()

            assert config_path.exists()
            assert config.get("test_key") == "test_value"

    def test_cert_directory_creation(self):
        """Test that cert directory can be created on Windows"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_dir = Path(tmpdir) / "certs"
            ssl_manager = rift.SSLCertificateManager(cert_dir=cert_dir)

            assert ssl_manager.cert_dir.exists()

    def test_file_path_validation_windows(self):
        """Test file path validation works on Windows"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(b"test content")

        try:
            validated_path = rift.validate_file_path(tmp_path)
            assert validated_path.exists()
            assert validated_path.is_file()
        finally:
            tmp_path.unlink()

    def test_file_path_validation_long_path_windows(self):
        """Test that long paths are rejected (Windows has 260 char limit historically)"""
        long_path = Path("x" * 5000 + ".txt")

        with pytest.raises(ValueError, match="too long"):
            rift.validate_file_path(long_path)

    def test_secret_code_generation(self):
        """Test that secret code generation works cross-platform"""
        code1 = rift.generate_secret_code()
        code2 = rift.generate_secret_code()

        assert code1 != code2
        assert "-" in code1
        parts = code1.split("-")
        assert len(parts) == 3
        assert parts[0].isdigit()

    def test_random_port_generation(self):
        """Test that random port generation works on Windows"""
        port = rift.get_random_port()

        assert 8000 <= port < 10000
        assert isinstance(port, int)

    def test_local_ip_detection(self):
        """Test that local IP can be detected on Windows"""
        local_ip = rift.get_local_ip()

        assert local_ip is not None
        assert isinstance(local_ip, str)
        # Should either return valid IP or fallback to localhost
        assert "." in local_ip

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_default_gateway_windows(self):
        """Test gateway detection falls back to netstat on Windows"""
        # This should not crash on Windows, even if it returns None
        gateway = rift.get_default_gateway()
        # Gateway might be None, which is okay - just shouldn't crash
        assert gateway is None or isinstance(gateway, str)

    def test_rate_limiter_cross_platform(self):
        """Test that rate limiter works on all platforms"""
        limiter = rift.RateLimiter(max_attempts=3, window_seconds=60)

        # Should allow first 3 attempts
        assert limiter.is_allowed("192.168.1.1")
        assert limiter.is_allowed("192.168.1.1")
        assert limiter.is_allowed("192.168.1.1")

        # Should block 4th attempt
        assert not limiter.is_allowed("192.168.1.1")

        # Different IP should still work
        assert limiter.is_allowed("192.168.1.2")

    def test_wordlist_loading(self):
        """Test that wordlist can be loaded (or gracefully falls back)"""
        words = rift.load_wordlist()

        # Either loads wordlist or returns None (fallback to generated words)
        assert words is None or (isinstance(words, list) and len(words) > 0)

    def test_pronounceable_word_generation(self):
        """Test fallback word generation when wordlist unavailable"""
        word = rift.generate_pronounceable_word(6)

        assert len(word) == 6
        assert word.isalpha()

    def test_logging_setup_cross_platform(self):
        """Test that logging can be set up on all platforms"""
        # Should not crash on any platform
        rift.setup_logging(verbose=True)
        rift.setup_logging(verbose=False)

    def test_color_detection_windows(self):
        """Test ANSI color detection on Windows"""

        # Mock a stream object
        class MockStream:
            def isatty(self):
                return True

        # Should work without crashing
        result = rift._should_use_color(MockStream())
        assert isinstance(result, bool)

    def test_config_json_serialization(self):
        """Test that config can be serialized to JSON on Windows"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config = rift.Config(config_path=config_path)

            config.set("port", 8080)
            config.set("string_value", "test")
            config.save()

            # Load it back
            config2 = rift.Config(config_path=config_path)
            assert config2.get("port") == 8080
            assert config2.get("string_value") == "test"


class TestPortForwardingMethods:
    """Test that port forwarding method classes can be instantiated"""

    def test_upnp_method_init(self):
        """Test UPnP method can be created"""
        method = rift.UPnPMethod()
        assert method.name() == "UPnP"
        assert not method.is_tunnel()

    def test_natpmp_method_init(self):
        """Test NAT-PMP method can be created"""
        method = rift.NATPMPMethod()
        assert method.name() == "NAT-PMP"
        assert not method.is_tunnel()

    def test_cloudflared_method_init(self):
        """Test cloudflared method can be created"""
        method = rift.CloudflaredMethod()
        assert method.name() == "cloudflared"
        assert method.is_tunnel()

    def test_pinggy_method_init(self):
        """Test pinggy.io method can be created"""
        method = rift.PinggyMethod()
        assert method.name() == "pinggy.io"
        assert method.is_tunnel()


class TestVersionInfo:
    """Test version information"""

    def test_get_version(self):
        """Test that version can be retrieved"""
        version = rift._get_version()
        assert version is not None
        assert isinstance(version, str)
