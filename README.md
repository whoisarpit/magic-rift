# Rift

One-time file sharing from your machine.

Rift starts a temporary server, prints a share link, and shuts down after the first successful download.

## Install

[pipx](https://pipx.pypa.io/stable/installation/#installing-pipx) is recommended for Python tool installation:

```bash
pipx install magic-rift
```

or if you prefer [uv](https://docs.astral.sh/uv/#installation), you can install with:

```bash
uv tool install magic-rift
```

For easier and more reliable sharing, install `cloudflared` (if not already installed): https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/

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

## Configuration Path

Rift stores config at:

```text
~/.config/rift/config.json
```

## License

MIT
