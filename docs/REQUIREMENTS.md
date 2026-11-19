# Ipdoit for CardputerZero: Requirements

A 320x170 LVGL app for managing the UFW firewall from the CardputerZero launcher.
Keyboard-driven (46-key matrix).

## v0.1.0 (in scope)

### 1. Status and on/off
- Show whether UFW is active, and the default policies (incoming / outgoing / routed),
  from `ufw status verbose`.
- Enable or disable the firewall. Enabling uses `ufw --force enable`, because ufw's own
  "may disrupt existing ssh connections" prompt cannot be answered in the app; Ipdoit's
  SSH lockout guard (below) replaces it.

### 2. List and delete rules
- Numbered list from `ufw status numbered`, scrollable, showing action, direction,
  target and source. IPv6 copies are marked `(v6)`.
- Delete the selected rule with `ufw --force delete <n>` after confirming.
- The list is re-read after every change, because rule numbers shift after a delete.

### 3. Add rules, two ways
- **Form** (default): action (allow / deny / reject / limit), direction (in / out),
  port or range, protocol (tcp / udp / any), source (any, IP, or CIDR), optional
  comment.
- **Presets**: SSH (22/tcp, limit), HTTP (80/tcp), HTTPS (443/tcp), DNS (53),
  mDNS (5353/udp). A preset fills the form so it can be adjusted before applying.
- **Free-form**: type what follows `ufw`, for example
  `allow from 192.168.1.0/24 to any port 22 proto tcp`.
- Both paths are checked with `ufw --dry-run <rule>` before anything is applied;
  errors are shown and nothing changes.

### 4. Listening ports
- List the ports that services are listening on, from `ss -tulpn` (run as root so
  every process name is shown): protocol, port, bound address and process.
- For each, show whether UFW lets it in from outside:
  - **Allowed**: an allow rule matches from any source;
  - **Limited**: a limit rule matches;
  - **Partial**: allowed only from some sources (for example a LAN subnet);
  - **Blocked**: no allow/limit rule matches and incoming is denied or rejected, or a
    deny/reject rule matches first;
  - **Local only**: bound to a loopback address (127.0.0.1 or ::1), so not reachable
    from outside whatever the firewall says;
  - **Firewall off**: UFW is inactive, so everything that listens is reachable.
- Rules are matched in order, first match wins, as ufw does: by port (and port ranges),
  protocol, and direction in. IPv4 and IPv6 are judged separately, so a port can be
  allowed on one and blocked on the other.
- Refreshed when the page opens and after every rule change.

### 5. Root access
- sudo password asked on launch (the launcher starts apps as a normal user), passed to
  `sudo -S` over stdin, kept in memory only, never written to disk or logs.
- Skipped when running as root or with passwordless sudo.

### 6. Safety
- **Confirm every change**: show the exact ufw command(s) and the dry-run result;
  Enter applies, Esc cancels.
- **SSH lockout guard**: find the SSH port(s) sshd listens on (`ss -tlnp`) and whether
  any SSH sessions are open (`ss -tn state established`). Warn, and require a second,
  explicit confirm, when a change would leave SSH blocked:
  - enabling the firewall while incoming is denied and no rule allows or limits the
    SSH port;
  - deleting the last rule that allows or limits the SSH port;
  - adding a deny or reject rule that covers the SSH port.
  If sshd is not running, no warning is shown.
- **Undo last change**: before each rule change, back up `/etc/ufw/user.rules` and
  `/etc/ufw/user6.rules` into `/var/lib/ipdoit/backups/` (last 10 kept). Undo restores
  the most recent backup and runs `ufw reload`. Undo covers rules only: it never turns
  the firewall on or off, and enabling or disabling is not recorded as an undoable
  change.

### 7. Packaging
- Depends on `ufw` and `sudo`.
- No background service. (The store rejects packages whose bundled systemd service runs
  as root, and Ipdoit does not need one.)

## Planned (not in v0.1.0)

- Logging level (`ufw logging off|low|medium|high`) and a viewer for recent
  `[UFW BLOCK]` log lines.
- From the listening-ports list, pick a port to open the add-rule form prefilled
  with its port and protocol.
- Application profiles (`ufw app list`, `ufw allow <profile>`).
- Changing default policies, and routed/forward rules.
- Undo history beyond the last change (browse and restore any of the kept backups).

## Implementation notes

- Reuse Updoit's process runner and privilege handling (fork/exec with merged output,
  cancel, `sudo -k -S` with the password wiped after use).
- Run ufw with `LC_ALL=C` so its output can be parsed.
- All ufw calls run on a worker thread; the UI polls its state, as in Updoit.

## Open questions

- Does the CardputerZero image ship `ufw`, and does its kernel have the netfilter
  support ufw needs (iptables-nft)? Must be checked on hardware.
- Is sshd enabled by default on the device (SSH over Wi-Fi or USB)? This decides how
  often the lockout guard matters.
- The blocked/allowed verdict follows ufw's user rules; rules added outside ufw
  (`/etc/ufw/before.rules`, raw iptables/nftables) are not evaluated. The page should
  say so.
