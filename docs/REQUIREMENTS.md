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
- **Merged list with a switch per port** (added after 0.1.4): the list also shows ports
  that have rules but nothing listening (marked "not listening", listed last). Enter on a
  port cycles its switch **Blocked > LAN > Allowed**:
  - Blocked: no rule opens it (the default, since incoming is denied);
  - LAN: a My network (whitelisted only) rule;
  - Allowed: an allow rule from anywhere (`limit` for the SSH port).
  A switch change applies at once with a toast and is one undo step (U). It only asks
  first when it would lock out SSH. A `*` marks ports where another rule (a range, a
  specific source) decides more than the switch shows. Local-only ports cannot be toggled.

### 5. My network (follows the device, with a network whitelist)
- **Current subnet**: worked out without root from `ip -o addr show` and `ip route`.
  For each interface that is up, its IPv4 subnet in CIDR form (for example
  `192.168.1.0/24`) and its global IPv6 prefix. Loopback, link-local
  (`169.254.0.0/16`, `fe80::/10`) and down interfaces are skipped.
- **Network identity**: each network is identified by its default gateway's MAC address
  (from `ip route` plus `ip neigh`), together with its subnet. A link with no gateway,
  such as a direct USB connection, is identified by interface name and subnet.
- **Whitelist**: a network is either **whitelisted** (trusted) or not. Every network
  starts off not whitelisted; Ipdoit never asks on its own.
  - A **Whitelist this network** button (on the status page) adds the current network,
    showing its subnet and gateway first. When the current network is already
    whitelisted, the button removes it instead.
  - A Networks page lists whitelisted networks and can remove any of them.
  - The whitelist is kept in `/etc/ipdoit-for-cardputer-zero/whitelist.conf` (root-owned).
- **"My network" as a rule source**, with two choices per rule:
  - **My network, whitelisted only** (default): the rule exists only while the device is
    on a whitelisted network, with that network's subnet as the source. On any other
    network it is removed, so nothing extra is open on, say, public Wi-Fi.
  - **My network, any network**: the rule follows the current subnet everywhere,
    whitelisted or not.
- **Following the device**: "My network" rules are kept as templates in
  `/etc/ipdoit-for-cardputer-zero/mynet-rules.conf` (action, port, protocol, scope). The ufw rules made from
  them carry a comment tag (`ipdoit:mynet:<id>`), so they can be found and replaced.
  An optional NetworkManager dispatcher script (shipped as
  `/usr/lib/ipdoit-for-cardputer-zero/nm-dispatcher`, enabled by the user linking it into
  `/etc/NetworkManager/dispatcher.d/`; the store rejects `usr/lib/NetworkManager/`), run as root by NetworkManager whenever a connection comes up, goes down or gets a new
  address, deletes the tagged rules and re-adds them for the current subnet(s) and
  whitelist. Ipdoit does the same when it opens, in case an event was missed.
- These automatic rewrites are not undoable changes; undo covers rule changes made in
  the app.
- The add-rule form offers sources: any, **My network (whitelisted only)**,
  **My network (any network)**, or a typed IP/CIDR. Presets can use either My network
  option, for example SSH from My network (whitelisted only).
- On the listening-ports page, a port allowed only from My network shows
  **LAN only (whitelisted)** or **LAN only**.

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
- **SSH exception**: SSH is allowed by default. When the firewall is turned on, and when
  the package is installed, Ipdoit adds `limit <port>/tcp` (comment "ipdoit: SSH") for
  each port sshd listens on (or, if sshd is enabled but not running, its configured port)
  when nothing else lets it in. Everything else stays blocked by default.
- **Undo last change**: before each rule change, back up `/etc/ufw/user.rules` and
  `/etc/ufw/user6.rules` into `/var/lib/ipdoit-for-cardputer-zero/backups/` (last 10 kept). Undo restores
  the most recent backup and runs `ufw reload`. Undo covers rules only: it never turns
  the firewall on or off, and enabling or disabling is not recorded as an undoable
  change.

### 8. Packaging
- Depends on `ufw` and `sudo`.
- No systemd service. (The store rejects packages whose bundled systemd service runs
  as root.) The NetworkManager dispatcher script is a root hook, not a service; it ships
  inactive under `usr/lib/<pkg>/` and must be root-owned and mode 0755 or NetworkManager ignores it.
- Removing the package deletes the tagged My network rules, the dispatcher link and
  `/etc/ipdoit-for-cardputer-zero` (on purge).

## Design decisions

1. **Deleting a My network rule**: the rules list shows each My network rule as one
   entry (its template), not the live ufw rules made from it. Deleting it removes the
   template and every live ufw rule tagged with its id. Deleting only the ufw rule would
   make the next sync bring it back.
2. **Undo and My network**: backups also include `/etc/ipdoit-for-cardputer-zero/mynet-rules.conf`. Undo
   restores it with the rules files, then re-syncs My network for the current network,
   so rules for a previous network are not brought back. Whitelist changes are not
   undoable changes.
3. **One change at a time**: ufw has no locking of its own. The app and the dispatcher
   both take `/run/ipdoit-for-cardputer-zero.lock` (flock) before changing anything.
4. **Free-form is limited to rule commands**: only `allow`, `deny`, `reject` and
   `limit`, optionally after `insert N`. Commands such as `reset`, `disable`,
   `default`, `delete`, `logging` and `route` are refused. Input is split into
   arguments and never passed through a shell.
5. **Pages**: Status (on/off, default policies, Whitelist this network, Undo), Rules
   (list, delete, add), Ports, Networks. Left/Right switch pages; the add-rule form
   opens from Rules. On-screen name: "Ipdoit".
6. **Code**: Updoit's process runner and sudo handling are copied into this repo, not
   shared as a library.
7. **Root helper**: every privileged step goes through one program,
   `/usr/lib/ipdoit-for-cardputer-zero/ipdoit-helper`, run with sudo by the app and directly by the
   dispatcher. It takes the lock, makes the backup, runs ufw, and syncs My network.
   Reading the firewall state is one helper call that prints ufw status, the rules
   (from the tuples in `/etc/ufw/user.rules` and `user6.rules`, which are root-only),
   and the listening sockets. User deletes find the rule's current number by matching
   its tuple inside the lock, so a number that shifted in the meantime is never deleted.

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
- A gateway MAC can be copied by another router, so whitelisting by MAC is a convenience,
  not strong security. The Networks page should say so.
- Store check: AppBuilder's `czdev publish` only rejects systemd `.service` units under
  `lib/systemd/system/`, `usr/lib/systemd/system/` or `etc/systemd/system/` that would
  run as root (`find_root_services` in `scripts/czdev/publish.py`). The store's path check
  rejects `usr/lib/NetworkManager/dispatcher.d/<pkg>` (not a `usr/lib/<pkg>/` directory),
  so the hook ships in `usr/lib/<pkg>/` and is opt-in.
- The blocked/allowed verdict follows ufw's user rules; rules added outside ufw
  (`/etc/ufw/before.rules`, raw iptables/nftables) are not evaluated. The page should
  say so.
