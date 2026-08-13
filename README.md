# CloudShark-compatible receiver for Meraki packet captures

A minimal self-hosted stand-in for CloudShark's upload API
(https://support.qacafe.com/cloudshark/api/upload), so Meraki Dashboard's
"Stream to CloudShark" packet capture option lands the file on infrastructure
you control instead of cloudshark.org or a licensed CS Enterprise instance.

Not a packet decoder/viewer - it just accepts the upload, saves the raw
capture, and lists/serves what's landed. Open the `.pcap` in Wireshark
yourself.

TLS uses Cloudflare's **DNS-01** ACME challenge (via the
`caddy-dns/cloudflare` plugin, built into the custom `Dockerfile.caddy`)
rather than the HTTP-01/TLS-ALPN-01 challenges, specifically so this doesn't
need port 80 or 443 - pick whatever port you can actually forward.

## Requirements

- A domain (or subdomain) with DNS managed by **Cloudflare**
- A public IP that's genuinely yours (home connection with port-forwarding
  access, or a VPS/cloud VM) - not anything behind a shared reverse proxy
- One port forwarded from your public IP to wherever this stack runs
- Docker + Docker Compose

## Setup

1. `cp .env.example .env` and fill in every value (see comments in the file
   for where each one comes from - receiver token, domain, port, Cloudflare
   API token).
2. Point DNS: create an **A record** (DNS only / grey-cloud, NOT proxied)
   for `CLOUDSHARK_DOMAIN` pointing at your public IP.
3. Forward `CLOUDSHARK_PORT` (TCP) from your router/firewall to the host
   running this stack.
4. `docker compose up -d --build`
5. Check it's reachable: `curl https://<CLOUDSHARK_DOMAIN>:<CLOUDSHARK_PORT>/`
   should return `ok`.
6. In Meraki Dashboard → **Network-wide → General → Packet capture** →
   enable CloudShark integration:
   - **CloudShark URL:** `https://<CLOUDSHARK_DOMAIN>:<CLOUDSHARK_PORT>`
   - **CloudShark API key:** your `CLOUDSHARK_RECEIVER_TOKEN`
7. Trigger a capture from **Network-wide → Monitor → Packet Capture**,
   output set to "Stream to CloudShark".

## Using it

- Received captures: `https://<CLOUDSHARK_DOMAIN>:<CLOUDSHARK_PORT>/captures?token=<CLOUDSHARK_RECEIVER_TOKEN>`
  lists everything with download links (the token is required as a query
  param - see Security notes below for why this isn't IP-restricted
  instead).
- Raw files + an `index.json` manifest persist in the `captures` Docker
  volume (`docker volume inspect cloudshark_receiver_captures` to find the
  path, or `docker compose cp receiver:/data/captures ./captures` to copy
  them out).
- Caddy's access log (JSON, one line per request) is in the `caddy_data`
  volume at `/data/caddy_access.log` - useful for diagnosing anything that
  doesn't show up in the receiver's own log (i.e. anything that fails before
  reaching the app).

## Security notes

- `/captures` (browsing/downloading received files) requires a `?token=...`
  query param matching `CLOUDSHARK_RECEIVER_TOKEN`, enforced in `server.py`.
  This is deliberately not IP-based - Docker Desktop on Windows doesn't
  preserve real client source IPs for published ports, so an IP allowlist
  at the proxy layer would be a no-op regardless of who's actually
  connecting (confirmed empirically). On a platform that does preserve
  source IPs (native Linux, a VPS, etc.), an IP-based restriction in the
  Caddyfile would work fine there instead.
- Captures may contain unencrypted payload data (credentials, personal
  data, etc. depending on what was captured) - the transport here is TLS,
  but treat the stored files with the same care you'd give the original
  traffic.
- Tear down (`docker compose down`) and remove the port-forward when you're
  not actively expecting a capture, if you'd rather not leave it exposed
  between uses.
