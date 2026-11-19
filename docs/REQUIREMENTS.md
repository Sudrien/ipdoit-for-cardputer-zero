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
  port or range, protocol (tcp / udp / any), source (any, My network, or a typed IP
  or CIDR), optional comment.
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

### 5. My network (follows the device, with trusted networks)
- **Current subnet**: worked out without root from `ip -o addr show` and `ip route`.
  For each interface that is up, its IPv4 subnet in CIDR form (for example
  `192.168.1.0/24`) and its global IPv6 prefix. Loopback, link-local
  (`169.254.0.0/16`, `fe80::/10`) and down interfaces are skipped.
- **Network identity**: each network is identified by its default gateway's MAC address
  (from `ip route` plus `ip neigh`), together with its subnet. A link with no gateway,
  such as a direct USB connection, is identified by interface name and subnet.
- **Trust**: each network can be marked **trusted** or **untrusted**. A network seen
  for the first time is untrusted until marked. When Ipdoit opens on an unmarked
  network it asks "Trust this network?" and shows its subnet and gateway. Marks are kept
  in `/etc/ipdoit/networks.conf` (root-owned) and can be changed from a Networks page.
- **"My network" as a rule source**, with two choices per rule:
  - **My network, trusted only** (default): the rule exists only while the device is on
    a trusted network, with that network's subnet as the source. On an untrusted network
    it is removed, so nothing extra is open on, say, public Wi-Fi.
  - **My network, any network**: the rule follows the current subnet everywhere,
    trusted or not.
- **Following the device**: "My network" rules are kept as templates in
  `/etc/ipdoit/mynet-rules.conf` (action, port, protocol, scope). The ufw rules made from
  them carry a comment tag (`ipdoit:mynet:<id>`), so they can be found and replaced.
  A NetworkManager dispatcher script (`/etc/NetworkManager/dispatcher.d/90-ipdoit`),
  run as root by NetworkManager whenever a connection comes up, goes down or gets a new
  address, deletes the tagged rules and re-adds them for the current subnet(s) and trust
  state. Ipdoit does the same when it opens, in case an event was missed.
- These automatic rewrites are not undoable changes; undo covers rule changes made in
  the app.
- The add-rule form offers sources: any, **My network (trusted only)**,
  **My network (any network)**, or a typed IP/CIDR. Presets can use either My network
  option, for example SSH from My network (trusted only).
- On the listening-ports page, a port allowed only from My network shows
  **LAN only (trusted)** or **LAN only**.

### 6. Root access
- sudo password asked on launch (the launcher starts apps as a normal user), passed to
  `sudo -S` over stdin, kept in memory only, never written to disk or logs.
- Skipped when running as root or with passwordless sudo.

### 7. Safety
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

### 8. Packaging
- Depends on `ufw` and `sudo`.
- No systemd service. (The store rejects packages whose bundled systemd service runs
  as root.) The NetworkManager dispatcher script is a root hook, not a service; it must
  be root-owned and mode 0755 or NetworkManager ignores it.
- Removing the package deletes the tagged My network rules, the dispatcher script and
  `/etc/ipdoit` (on purge).

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
- Does the device image use NetworkManager? If not (for example plain dhcpcd), the
  dispatcher needs a dhcpcd hook instead.
- A gateway MAC can be copied by another router, so trust by MAC is a convenience, not
  strong security. The Networks page should say so.
- Does the store's "no root service" check treat a NetworkManager dispatcher script as
  acceptable?
- The blocked/allowed verdict follows ufw's user rules; rules added outside ufw
  (`/etc/ufw/before.rules`, raw iptables/nftables) are not evaluated. The page should
  say so.
