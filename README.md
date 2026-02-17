# Rift

One-time file sharing from your machine.

Rift starts a temporary server, prints a share link, and shuts down after the first successful download.

## Install

Python 3.8+ required.

```bash
pipx install magic-rift
```

Or:

```bash
python -m pip install --user pipx
python -m pipx ensurepath
pipx install magic-rift
```

If you prefer `uv`:

```bash
uv tool install magic-rift
```

If you prefer `pip`:

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

Recommended for easiest sharing:

```bash
rift share file.zip --method cloudflared
```

Disable TLS:

```bash
rift share file.zip --no-ssl
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

If automatic forwarding/tunneling fails, Rift exits and does not print a public link.

For most users, installing `cloudflared` gives the smoothest setup.

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
