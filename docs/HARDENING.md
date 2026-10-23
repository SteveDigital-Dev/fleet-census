# Home fleet hardening checklist

A plain-language baseline for a homelab or studio. Do it top to bottom; the
first sections matter most. `fleet.py report` flags many of these for you.

## 1. Updates (the biggest win)
- [ ] Turn on automatic security updates.
  - Debian / Ubuntu / Mint / Raspberry Pi OS: `sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`
  - macOS / iOS: Settings → General → Software Update → Automatic Updates (include "Security Responses")
  - Arch-based: no auto-update by design, so run `sudo pacman -Syu` weekly
- [ ] After updating something that runs as a service (PHP, web servers, databases), **restart it**. The old code keeps running until you do.
- [ ] Retire anything that no longer gets security updates (old OS versions, PHP below 8.2, etc.).

## 2. Network exposure
- [ ] Don't port-forward on your router. If something must be reachable from outside, use Tailscale (or Cloudflare Tunnel / Tailscale Funnel).
- [ ] Turn off UPnP on the router.
- [ ] Turn on the host firewall.
  - Linux: `sudo ufw allow OpenSSH` (do this first!), then `sudo ufw default deny incoming`, `sudo ufw allow in on tailscale0`, `sudo ufw enable`
  - macOS: System Settings → Network → Firewall
- [ ] AI tools often ship with **no login at all**. Make them listen only on `127.0.0.1` or your Tailscale IP, never `0.0.0.0`:
  - Ollama: `OLLAMA_HOST=127.0.0.1`
  - ComfyUI: don't use `--listen` unless you pass your Tailscale IP
  - Jupyter, Gradio, LM Studio, Open WebUI: same idea
- [ ] Never expose the Docker API (port 2375) or databases (Redis, Postgres, MySQL) to the network.

## 3. Tailscale
- [ ] Replace the default "everyone can reach everything" policy with **ACLs/grants**: tag machines by role (`tag:server`, `tag:iot`, `tag:guest`) and allow only what each needs.
- [ ] Give friends or guests their own tag that can't reach your personal machines.
- [ ] Turn on **tailnet lock** so new devices can't join without your approval.
- [ ] Remove old devices from the admin console.
- [ ] Use **Tailscale SSH** or keep SSH listening only on the tailnet.

## 4. SSH
- [ ] Use SSH keys, then turn off passwords: `PasswordAuthentication no` in `/etc/ssh/sshd_config`, then restart sshd.
- [ ] `PermitRootLogin no`.
- [ ] `fail2ban` on anything reachable from a network you don't control.

## 5. Accounts and secrets
- [ ] 2FA on everything important: email, GitHub, Google/Apple, Tailscale, your password manager.
- [ ] Keep secrets in one place (Bitwarden/Vaultwarden, 1Password, `pass`), not scattered in dotfiles.
- [ ] Before you push dotfiles or configs anywhere, scan them with `gitleaks detect` or `trufflehog`.
- [ ] Use fine-grained, short-lived tokens (GitHub fine-grained PATs, scoped API keys).
- [ ] Change default passwords on Pis, routers, cameras and printers.

## 6. Disks and retiring machines
- [ ] Encrypt laptops: FileVault on macOS, LUKS on Linux (chosen at install).
- [ ] Before you retire or sell a machine, remove it from Tailscale, remove its SSH keys from your other machines, rotate any tokens stored on it, then wipe the disk.

## 7. AI agents and automation
- [ ] Run each agent or bot as its **own non-root user** (or in a container) with access only to the folders it needs.
- [ ] Treat anything an agent reads (web pages, docs, repos, emails) as untrusted. Prompt injection is real. Require a human OK before destructive actions.
- [ ] ComfyUI custom nodes, browser extensions and plugins run code. Install only what you use, from authors you trust.
- [ ] Pin versions of models, nodes and plugins; update deliberately.

## 8. Microcontrollers and IoT
- [ ] Put Wi-Fi gadgets (ESP32, smart plugs, cameras) on a separate guest or IoT network.
- [ ] Don't commit Wi-Fi passwords or API keys in firmware repos. Use a `secrets.h` that's in `.gitignore`.
- [ ] Turn off OTA update endpoints when not in use, or protect them with a password.

## 9. Backups and monitoring
- [ ] 3-2-1 backups: three copies, on two kinds of media, with one offsite. **Test a restore once.**
- [ ] Re-run the census monthly (or after big changes) and read the report.
- [ ] Subscribe to the [CISA alerts](https://www.cisa.gov/news-events/cybersecurity-advisories) and your distro's security announcements, or use `watch/WATCH-PROMPT.md`.

## References
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Tailscale docs (ACLs, Tailscale SSH, tailnet lock)](https://tailscale.com/kb)
- [Raspberry Pi: securing your Pi](https://www.raspberrypi.com/documentation/computers/configuration.html)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [gitleaks](https://github.com/gitleaks/gitleaks)
