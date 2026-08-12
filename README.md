# CloudShark-compatible receiver for Meraki packet captures

A minimal self-hosted stand-in for CloudShark's upload API
(https://support.qacafe.com/cloudshark/api/upload), so Meraki Dashboard's
"Stream to CloudShark" packet capture option lands the file on infrastructure
you control instead of cloudshark.org or a licensed CS Enterprise instance.

Not a packet decoder/viewer - it just accepts the upload, saves the raw
capture, and lists/serves what's landed. Open the `.pcap` in Wireshark
yourself.

## Why it's built this way (read this before changing the Caddyfile)

Two non-obvious things this setup works around, found the hard way:

1. **Cloudflare Tunnel (quick or named) does not work here.** Meraki's
   backend resolves the CloudShark URL's hostname to an IP and connects
   using that literal IP rather than the hostname. Cloudflare's shared edge
   routes by Host/SNI and rejects direct-IP connections with a 403 (anti
   domain-fronting protection) - this happens regardless of tunnel type.
   You need an endpoint with a genuinely dedicated public IP (a port-forward
   to your own IP, or a VM with its own IP). This stack assumes the latter.

2. **Meraki's HTTP client sends the raw resolved IP as the HTTP `Host`
   header, even though it correctly sends the real hostname as the TLS
   SNI.** A Caddyfile site block matching only on the hostname
   (`cloudshark.example.com:8443 { ... }`) will pass the TLS handshake but
   then fail to route the HTTP request, causing Meraki's client to see a
   broken connection mid-upload ("Error writing to server"). The fix is the
   catch-all in the Caddyfile: `{$CLOUDSHARK_DOMAIN}:{$CLOUDSHARK_PORT}, :{$CLOUDSHARK_PORT}`
   matches the real hostname (for automatic cert management) **and** any
   other Host header on that port (so the raw-IP request still gets
   proxied).

Also: TLS uses Cloudflare's **DNS-01** ACME challenge (via the
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

- Received captures: `https://<CLOUDSHARK_DOMAIN>:<CLOUDSHARK_PORT>/captures`
  lists everything with download links.
- Raw files + an `index.json` manifest persist in the `captures` Docker
  volume (`docker volume inspect cloudshark_receiver_captures` to find the
  path, or `docker compose cp receiver:/data/captures ./captures` to copy
  them out).
- Caddy's access log (JSON, one line per request) is in the `caddy_data`
  volume at `/data/caddy_access.log` - useful for diagnosing anything that
  doesn't show up in the receiver's own log (i.e. anything that fails before
  reaching the app).

## Security notes

- This is a token-gated upload endpoint on the open internet. Background
  scanner/bot traffic hitting random paths is normal and harmless (nothing
  else is exposed, wrong tokens get a 401) - just don't reuse
  `CLOUDSHARK_RECEIVER_TOKEN` anywhere else.
- The Cloudflare API token only needs "Edit zone DNS" scoped to the one
  zone - don't grant it broader access.
- Captures may contain unencrypted payload data (credentials, personal
  data, etc. depending on what was captured) - the transport here is TLS,
  but treat the stored files with the same care you'd give the original
  traffic.
- Tear down (`docker compose down`) and remove the port-forward when you're
  not actively expecting a capture, if you'd rather not leave it exposed
  between uses.
