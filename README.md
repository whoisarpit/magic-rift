# Rift

One-time file sharing from your machine.

Rift starts a temporary server, prints a share link, and shuts down after the first successful download.

## Install

Python 3.8+ required.

```bash
uv tool install magic-rift
```

Or:

```bash
uvx magic-rift --version
```

Or with pip:

```bash
pip install magic-rift
```

## Quick Start

Share a file:

```bash
rift share /path/to/file.pdf
```

Rift prints a disposable link like:

```text
https://PUBLIC_IP:PORT/4-crystal-salmon
```

After one successful download, the server exits and the link stops working.

Stop manually anytime with `Ctrl+C`.

## Most Useful Commands

Share with random port (default):

```bash
rift share file.zip
```

Share on a fixed port:

```bash
rift share file.zip --port 9000
```

Disable TLS:

```bash
rift share file.zip --no-ssl
```

Set default port:

```bash
rift config set port 9000
```

View config:

```bash
rift config list
```

Reset config:

```bash
rift config reset
```

## How Connectivity Works

Rift tries methods in this order:

1. `cloudflared` (if installed)
2. `natpmp`
3. `upnp`
4. `localhost.run` (SSH tunnel)

If automatic forwarding/tunneling fails, Rift still runs locally and tells you to configure routing manually.

## Security Notes

- Links are one-time and include a random secret path.
- Files are served directly from your machine.
- HTTPS may use a self-signed cert by default, which can show browser warnings.
- If cert setup is unavailable, Rift can fall back to HTTP.
- No built-in authentication. Encrypt sensitive files before sharing.

## Troubleshooting

Public IP detection failed:

- Check your public IP manually.
- Retry with a fixed method, for example:

```bash
rift share file.zip --method cloudflared
```

Port in use:

```bash
rift share file.zip --port 9001
```

Permission error:

```bash
chmod +r file.zip
```

## Configuration Path

Rift stores config at:

```text
~/.config/rift/config.json
```

## License

MIT
