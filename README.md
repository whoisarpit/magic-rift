# Rift

**Disposable file sharing via your public IP**

Share files from your personal computer via a one-time-use link. Like magic-wormhole but self-hosted. No third-party services required for direct sharing from your PC.

## Features

- **Disposable links** - Auto-shutdown and cleanup after one download (like wormhole)
- **Random ports** - Uses random available port (8000-10000) for each share
- **Secret URLs** - Obscure URLs like `http://ip:port/4-crystal-salmon` hide filenames
  - Uses EFF's diceware wordlist (7776 words, bundled)
  - Falls back to pronounceable random words if wordlist missing
- **Zero-config** - Automatic UPnP port forwarding (when available)
- **Auto-cleanup** - Removes UPnP port forwarding rules automatically on exit
- **Direct sharing** from your PC without any third-party services
- **Automatic public IP detection** - no manual configuration needed
- **Public accessibility** via standard web browser
- **Temporary availability** - share only when you want
- **Cross-platform** - works on Windows, macOS, and Linux
- **Python standard library core** - optional external tools for trusted certs/tunnels
- **Simple setup** - one command to share

## How It Works

Rift creates a local HTTP server on your PC, automatically configures port forwarding via UPnP (if available), and detects your public IP address, giving you a shareable link instantly.

```
Your PC (HTTP Server) <---> Router (Auto UPnP) <---> Internet
```

## Prerequisites

1. **Python 3.8+** installed on your local machine
2. **UPnP enabled on your router** (most routers have this on by default) OR manual port forwarding
3. Your PC must remain powered on during sharing
4. **Optional:** OpenSSL installed for default self-signed HTTPS (Rift falls back to HTTP if unavailable)

## Automatic Setup (UPnP)

If your router supports UPnP, Rift will automatically:
1. Discover your router
2. Configure port forwarding
3. Remove the forwarding rule when you stop sharing

No manual configuration needed!

## Manual Router Setup (If UPnP Fails)

If UPnP is not available, you'll need to manually forward a port:

### General Steps:
1. Access your router's admin panel (usually http://192.168.1.1 or http://192.168.0.1)
2. Find "Port Forwarding" or "Virtual Server" settings
3. Add a new rule:
   - **External Port**: 8000 (or your preferred port)
   - **Internal Port**: 8000 (same as external)
   - **Internal IP**: Your PC's local IP (Rift will display this)
   - **Protocol**: TCP

### Enable UPnP on Your Router
Most modern routers have UPnP enabled by default. If not:
1. Access your router's admin panel
2. Look for "UPnP" or "Universal Plug and Play" in settings
3. Enable it and save

## Installation

1. Clone or download this repository:
   ```bash
   git clone <repository-url>
   cd rift
   ```

2. Make the script executable:
   ```bash
   chmod +x rift.py
   ```

3. (Optional) Add to PATH:
   ```bash
   sudo ln -s $(pwd)/rift.py /usr/local/bin/rift
   ```

## Quick Start

### Share a File

```bash
./rift.py share document.pdf
```

Output:
```
[PORT] Using random port: 8758

============================================================
Rift - Public File Sharing
============================================================

[UPnP] Discovering gateway...
[UPnP] Gateway found! Configuring port forwarding...
[UPnP] Local IP: 192.168.1.100
[UPnP] Port 8758 forwarded successfully

[IP] Detecting public IP address...
[HTTPS] Serving file: document.pdf
[HTTPS] Listening on port: 8758

============================================================
DISPOSABLE LINK (one-time use):
  https://123.45.67.89:8758/4-crystal-salmon
============================================================

Your public IP: 123.45.67.89
Secret code: 4-crystal-salmon
File: document.pdf

Waiting for download... (Press Ctrl+C to cancel)
```

When someone downloads the file:
```
[ACCESS] 93.184.216.34 - "GET /4-crystal-salmon HTTP/1.1" 200 -

[SUCCESS] File downloaded successfully!
[INFO] Shutting down server...
[HTTP] Stopping HTTP server...
[UPnP] Removing port forwarding...
[UPnP] Port mapping removed successfully
Rift stopped.

[INFO] Download complete. Exiting...
```

If UPnP fails, you'll see a message to manually configure port forwarding.

**Note:** Directory sharing is not supported with disposable links. You must share individual files.

### Use Custom Port

```bash
./rift.py share file.zip --port 9000
```

### Configure Default Port

```bash
./rift.py config set port 9000
```

### Stop Sharing

Press `Ctrl+C` to immediately stop sharing.

## Usage Examples

### Share a single file
```bash
rift share presentation.pptx
```
Output: `https://YOUR_IP:8758/7-forest-lunar` (random port, one-time use, auto-shutdown)

### Share on custom port (bypass random)
```bash
rift share file.zip --port 9000
```
Uses fixed port 9000 instead of random. Useful if you have specific firewall rules.

### Configure default port
```bash
rift config set port 9000
rift share file.zip
```
All shares will use port 9000 instead of random ports.

### View current configuration
```bash
rift config list
```

### Reset configuration to defaults
```bash
rift config reset
```
Removes all saved settings. Next share will use random port again.

## Command Reference

### Share Command

```bash
rift share <file> [options]
```

Options:
- `-p, --port` - Port to listen on (default: random port between 8000-10000)

### Config Command

```bash
rift config <action> [key] [value]
```

Actions:
- `set <key> <value>` - Set a configuration value
- `get [key]` - Get a configuration value (or all if no key)
- `list` - List all configuration values
- `reset` - Reset configuration to defaults (clears all settings)

Configuration keys:
- `port` - Default port to use (default: random). Set this to bypass random port selection.

## Security Considerations

### Best Practices

1. **Stop immediately after use** - Always terminate the server when done
2. **Share specific files** - Avoid sharing directories with sensitive files
3. **Monitor access** - Watch for unexpected connections in your terminal
4. **Use strong passwords** - Consider adding nginx authentication (see below)
5. **Firewall rules** - Only open necessary ports
6. **File encryption** - Encrypt sensitive files before sharing
7. **Temporary shares** - Use for short-term sharing only

### Security Features

- Server runs only while script is active
- Files never leave your PC
- Instant revocation by stopping the process
- No permanent exposure

### Limitations

- Trusted HTTPS is not always available automatically
- Self-signed HTTPS will show browser warnings
- No built-in authentication
- No access logs (unless configured)
- Public IP exposure

## Troubleshooting

### Cannot Detect Public IP
If Rift can't detect your public IP, you can find it manually:
- Visit https://whatismyipaddress.com/
- Run `curl ifconfig.me` in terminal
- Check your router's status page

### Port Already in Use
```bash
rift share file.pdf --port 8001
```

### Permission Denied
Make sure the file/directory is readable:
```bash
chmod +r file.pdf
```

### Connection Refused
1. Check port forwarding is configured correctly
2. Check firewall isn't blocking the port:
   ```bash
   # macOS
   sudo pfctl -d  # disable firewall temporarily for testing

   # Linux
   sudo ufw allow 8000
   ```
3. Verify the port is listening:
   ```bash
   netstat -an | grep 8000
   ```

### Router Behind CGNAT
If your ISP uses Carrier-Grade NAT (CGNAT), you won't have a true public IP. Solutions:
- Use a VPN service that provides a static IP
- Use a reverse proxy service like ngrok, CloudFlare Tunnel
- Contact your ISP for a public IP address

## Advanced: Adding HTTPS and Authentication

### Using nginx as Reverse Proxy

For HTTPS and authentication, install nginx on your PC:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Create password file:
```bash
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd username
```

### Using Cloudflare Tunnel (No Port Forwarding)

If you can't configure port forwarding:

```bash
cloudflared tunnel --url http://localhost:8000
```

This gives you a public URL without opening any ports.

## Dynamic DNS

If your public IP changes frequently, use a Dynamic DNS service:

1. Sign up for a DDNS service (e.g., No-IP, DuckDNS)
2. Install their client on your PC
3. Use your DDNS hostname instead of IP

Example:
```
http://myshare.ddns.net:8000/file.pdf
```

## Configuration File

Configuration is stored in `~/.config/rift/config.json`:

```json
{
  "port": 8000
}
```

## Comparison with Alternatives

| Feature | Rift | ngrok | SSH Tunnel | Dropbox |
|---------|------|-------|------------|---------|
| No third-party service | ✅ | ❌ | ❌ | ❌ |
| No SSH server needed | ✅ | ✅ | ❌ | ✅ |
| Auto port forwarding (UPnP) | ✅ | ✅ | ❌ | ✅ |
| Zero dependencies | ✅ | ❌ | ❌ | ❌ |
| Free | ✅ | Limited | ✅ | Limited |
| File stays on PC | ✅ | ✅ | ✅ | ❌ |
| Zero-config | ✅* | ✅ | ❌ | ✅ |

*If router supports UPnP

**Use Rift when:**
- Your router supports UPnP (most do)
- You want maximum simplicity (no external services)
- You want complete control over your data
- You need temporary, on-demand sharing

**Use alternatives when:**
- You're behind CGNAT (no public IP)
- UPnP is unavailable and you can't configure port forwarding
- You need HTTPS without setup
- You need persistent sharing

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## FAQ

**Q: Do I need a server?**
A: No! Rift runs entirely on your PC. If your router supports UPnP, you don't even need to configure port forwarding.

**Q: Do I need to configure my router?**
A: Usually no! If your router supports UPnP (most modern routers do), Rift will automatically configure port forwarding. Otherwise, you'll need to manually set it up once.

**Q: Is this secure?**
A: Basic security only. Rift can use HTTPS, but trusted certs depend on your network setup. For sensitive files, encrypt first.

**Q: Can I share multiple files?**
A: No. Disposable links only support single files for security. Share files one at a time.

**Q: What happens after download?**
A: The server automatically shuts down after one successful download. The link becomes invalid immediately.

**Q: Why secret URLs?**
A: Secret URLs (like `4-crystal-salmon`) hide your filename from URL scanners and make brute-force guessing impossible. They work like magic-wormhole codes.

**Q: What if my IP changes?**
A: Just re-run Rift and it will detect your new IP and give you an updated link. If using UPnP, it will automatically reconfigure the port forwarding.

**Q: Does the other person need Rift?**
A: No! They just click the link in any web browser.

**Q: Can multiple people download at once?**
A: No. The first successful download consumes the one-time link and Rift shuts down.

**Q: What is UPnP?**
A: UPnP (Universal Plug and Play) is a protocol that allows devices to automatically configure port forwarding on your router. Most modern routers have it enabled by default.
