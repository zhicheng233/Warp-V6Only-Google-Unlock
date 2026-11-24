# AGENTS.md

Guidance for AI agents working in `Warp-V6Only-Google-Unlock`.

## Project Overview

- **Purpose**: System-level Linux VPS utility that selectively routes Google, YouTube, and AI service traffic through Cloudflare WARP (WireGuard) while preserving native VPS direct connection speeds for general internet traffic.
- **Dual-Stack & IPv6-Only Adaptation**: Natively supports **Single-Stack IPv6 VPS (IPv6-Only)**, Dual-Stack, and IPv4-Only systems. On IPv6-only VPS, it establishes the WireGuard tunnel over Anycast IPv6 endpoints and enables both IPv6 unlocking and global outbound IPv4 access for target domains.
- **Key Files**:
  - `warp-google.sh`: Monolithic Bash script handling installation, probing, WireGuard/Dnsmasq configuration, policy routing, and uninstallation.
  - `README.md`: User documentation, domain matrix, and diagnostic references.
  - `.gitattributes`: Enforces `*.sh text eol=lf`.

## Critical Operational Gotchas

- **Platform & Privileges**: Must run on Linux (Debian, Ubuntu, CentOS, AlmaLinux, Rocky) with root privileges (`EUID == 0`). It will not run on Windows or unprivileged containers lacking `NET_ADMIN` and WireGuard support.
- **Strict LF Line Endings**: `warp-google.sh` MUST maintain UNIX line endings (`LF`). When editing on Windows, ensure your editor or git does not convert line breaks to `CRLF`, which causes `\r: command not found` syntax errors on Linux.
- **Single-Stack IPv6 Compatibility**:
  - Never hardcode `curl -4` for external API or probe calls; on IPv6-only machines, `-4` fails immediately. Use `$CF_CURL_OPT` or let curl auto-negotiate.
  - WireGuard endpoints on IPv6-only machines must be enclosed IPv6 addresses: e.g. `[2606:4700:d0::a29f:c001]:2408`.
  - DNS upstream in `/etc/resolv.conf` and `dnsmasq.d/` must include IPv6 nameservers (`2001:4860:4860::8888`, `2606:4700:4700::1111`) to prevent DNS resolution blackholes before or after WARP is configured.
  - **Single-Stack IPv4 Routing**: On IPv6-only VPS, the machine has no native IPv4 gateway in table `main`. The script assigns `default dev warp0` in table `main` and adds `oif warp0` / `from 172.16.0.0/12` policy routing rules to table 51820 so that all outbound IPv4 traffic routes through WARP while native IPv6 remains split-tunneled.
- **Immutable `/etc/resolv.conf`**: The script sets `chattr +i /etc/resolv.conf` pointing to `127.0.0.1` (backed up at `/etc/resolv.conf.warp.bak`). Any script modifying DNS must execute `chattr -i /etc/resolv.conf` before editing.
- **`systemd-resolved` Collision**: Port 53 must be freed for `dnsmasq`. The script explicitly stops and disables `systemd-resolved`.
- **Deliberate QUIC (UDP 443) Drop**: Mangle/filter rules deliberately REJECT UDP 443 for IPs in `warp_unlock`/`warp_unlock6` (`--reject-with icmp-port-unreachable` for IPv4 and `--reject-with icmp6-port-unreachable` for IPv6). This forces browsers to fall back to TCP (TLS 1.3), preventing HTTP/3 packet drops caused by WireGuard MTU issues. Do NOT remove this rejection.
- **Dual-Stack MSS Clamping & MTU**: WireGuard interface `warp0` uses MTU `1200` and iptables/ip6tables TCPMSS clamping (`--clamp-mss-to-pmtu`) to prevent TLS handshake drops (`ERR_CONNECTION_CLOSED`).

## Architecture & Code Flow (`warp-google.sh`)

1. **Environment Detection (`detect_network_environment`)**:
   - Detects IPv4 and IPv6 default routes via `ip -4 route` and `ip -6 route`.
   - Sets `IS_V6_ONLY=1`, `CF_CURL_OPT="-6"`, and selects IPv6 Anycast WARP endpoints (`[2606:4700:d0::a29f:c001]:2408`, etc.) when on an IPv6-only VPS.
2. **Detection (`check_native_songzhong`)**:
   - Probes native IPv6/IPv4 address.
   - Probes Google search frontend payload (`[1,null,null,...,"ISO-3166"]`) and YouTube Premium `contentRegion` (`[CN]`/`www.google.cn`).
3. **Registration & Refresh (`setup_warp_profile` / `refresh_warp_ip`)**:
   - Registers device with Cloudflare client API (`api.cloudflareclient.com/v0a2158/reg`) using random `INSTALL_ID` and `FCM_TOKEN`.
   - Activates account via PATCH `{"warp_enabled": true}`.
   - Saves credentials to `/etc/wireguard/warp-account.conf`.
   - When refreshing IP, sends `DELETE /reg/<DEV_ID>` to release the old IP before re-registering.
   - `ensure_clean_warp_region` retries up to 6 times to avoid `RU` and `CN` egress nodes.
4. **DNS Sniffing (`setup_dnsmasq_rules`)**:
   - Configures `/etc/dnsmasq.d/warp_unlock.conf` with dual-stack upstreams and `ipset=/<domain>/warp_unlock,warp_unlock6`.
   - Matches all subdomains under each configured root domain automatically.
   - Verifies configuration with `dnsmasq --test` before restarting.
5. **Policy Routing (`setup_routing_rules`)**:
   - Generates `/usr/local/bin/warp-route-apply.sh` managed by `warp-unlock.service`.
   - Pre-seeds Google global IPv4 and IPv6 CIDR subnets directly into ipsets `warp_unlock`/`warp_unlock6`.
   - Sets `net.ipv4.conf.all.rp_filter=0` to prevent asymmetric return packet drops.
   - Marks destination ipset traffic with `fwmark 51820` and routes via routing table `51820` through `warp0`.
   - Applies dual-stack TCPMSS clamping and QUIC REJECT rules.
6. **Clean Uninstallation (`auto_clean_old_warp`)**:
   - De-registers device with Cloudflare, unlocks `/etc/resolv.conf` (`chattr -i`), restores backup, stops services, destroys `warp0`, flushes routing table 51820, ipsets, and iptables/ip6tables rules.

## Adding New Domains / Services

When expanding the unlocked domain list:
1. Add `ipset=/<domain>/warp_unlock,warp_unlock6` under the appropriate category in `setup_dnsmasq_rules()` in `warp-google.sh` (and in the fallback block if critical).
2. Update the domain matrix table in `README.md`.

## Verification & Diagnostic Commands

Run on the target Linux VPS as root:

```bash
# Validate shell script syntax (offline)
bash -n warp-google.sh

# Run script interactively or headless
bash warp-google.sh
printf "1\n" | bash warp-google.sh      # Headless: Option 1 (Smart Install)
printf "3\n" | bash warp-google.sh      # Headless: Option 3 (Test unlock status)
printf "4\n" | bash warp-google.sh      # Headless: Option 4 (Full uninstall)

# Check WireGuard tunnel handshake and transferred bytes
wg show warp0

# Check real-time packet hits on policy routing rules
iptables -t mangle -L OUTPUT -v -n | grep warp_unlock
ip6tables -t mangle -L OUTPUT -v -n | grep warp_unlock6

# Verify native direct connection IPs (non-target traffic)
curl -4 -s ip.sb
curl -6 -s ip.sb

# Verify WARP exit IPs and locations
curl -s -4 --interface warp0 https://www.cloudflare.com/cdn-cgi/trace
curl -s -6 --interface warp0 https://www.cloudflare.com/cdn-cgi/trace
```
