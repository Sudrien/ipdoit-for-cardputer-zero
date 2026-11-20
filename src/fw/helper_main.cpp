/*
 * SPDX-License-Identifier: MIT
 */

// ipdoit-helper: every privileged Ipdoit step, run as root (via sudo from the app, or
// directly from the NetworkManager dispatcher). Changes happen under /run/ipdoit.lock.
//
//   state                                  print everything the app shows
//   enable | disable
//   dry-run <ufw rule args...>             validate and `ufw --dry-run`
//   add <ufw rule args...>                 backup, then `ufw <args>`
//   delete <4|6> <tuple>                   backup, delete the rule with this tuple
//   mynet-add <action> <proto> <port> <whitelisted|any> [comment]
//   mynet-delete <id>
//   whitelist-add <key> <subnet> [name]    key: gw:<mac> or if:<iface>
//   whitelist-remove <key> <subnet>
//   undo                                   restore the last backup
//   sync                                   rewrite My network rules for the current network
//   clear-mynet                            remove all live My network rules (uninstall)
//   port-set <port> <tcp|udp|any> <blocked|lan|allowed>
//                                          the Ports page switch (one undo step)
//   ssh-allow                              add "limit <port>/tcp" for sshd if nothing
//                                          allows it (run by enable and on install)

#include "logic.h"
#include "parse.h"
#include "process.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <sys/file.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace fw;

namespace {

const char* kUserRules = "/etc/ufw/user.rules";
const char* kUserRules6 = "/etc/ufw/user6.rules";
const char* kUfwDefaults = "/etc/default/ufw";
const char* kEtcDir = "/etc/ipdoit";
const char* kWhitelist = "/etc/ipdoit/whitelist.conf";
const char* kTemplates = "/etc/ipdoit/mynet-rules.conf";
const char* kBackupDir = "/var/lib/ipdoit/backups";
const char* kLock = "/run/ipdoit.lock";
constexpr size_t kKeepBackups = 10;

std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::ostringstream s;
    s << f.rdbuf();
    return s.str();
}

bool write_file(const std::string& path, const std::string& text) {
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f) return false;
        f << text;
        if (!f) return false;
    }
    ::chmod(tmp.c_str(), 0644);
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

int run(const std::vector<std::string>& argv, std::string& out) {
    out.clear();
    RunOptions opt;
    opt.argv = argv;
    opt.env = {{"LC_ALL", "C"}, {"LANG", "C"}};
    opt.on_line = [&out](const std::string& line) {
        out += line;
        out += '\n';
    };
    return run_process(opt);
}

int ufw(std::vector<std::string> args, std::string& out) {
    args.insert(args.begin(), "ufw");
    return run(args, out);
}

int ufw_print(const std::vector<std::string>& args) {
    std::string out;
    const int code = ufw(args, out);
    std::fputs(out.c_str(), stdout);
    return code;
}

// ------------------------------------------------------------------ lock

class Lock {
public:
    Lock() {
        fd_ = ::open(kLock, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (fd_ < 0) return;
        for (int i = 0; i < 300; ++i) { // up to 30 s
            if (::flock(fd_, LOCK_EX | LOCK_NB) == 0) {
                held_ = true;
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    ~Lock() {
        if (fd_ >= 0) ::close(fd_);
    }
    bool held() const { return held_; }

private:
    int fd_ = -1;
    bool held_ = false;
};

// ------------------------------------------------------------------ backups

std::vector<fs::path> list_backups() {
    std::vector<fs::path> out;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(kBackupDir, ec)) {
        if (e.is_directory()) out.push_back(e.path());
    }
    std::sort(out.begin(), out.end());
    return out;
}

fs::path make_backup() {
    char name[64];
    std::snprintf(name, sizeof(name), "%012lld-%06d", static_cast<long long>(std::time(nullptr)),
                  static_cast<int>(::getpid()) % 1000000);
    const fs::path dir = fs::path(kBackupDir) / name;
    std::error_code ec;
    fs::create_directories(dir, ec);
    for (const char* f : {kUserRules, kUserRules6, kTemplates}) {
        if (fs::exists(f, ec)) {
            fs::copy_file(f, dir / fs::path(f).filename(), fs::copy_options::overwrite_existing,
                          ec);
        }
    }
    auto all = list_backups();
    while (all.size() > kKeepBackups) {
        fs::remove_all(all.front(), ec);
        all.erase(all.begin());
    }
    return dir;
}

void drop_backup(const fs::path& dir) {
    std::error_code ec;
    fs::remove_all(dir, ec);
}

// ------------------------------------------------------------------ state pieces

std::vector<Network> current_networks() {
    std::string addrs, routes, neigh;
    run({"ip", "-o", "addr", "show", "up"}, addrs);
    run({"ip", "route", "show", "default"}, routes);
    run({"ip", "neigh", "show"}, neigh);
    auto nets = parse_networks(addrs, routes, neigh);
    // Right after a connection comes up the gateway is often not in the neighbour table
    // yet; without its MAC a whitelisted network would look unknown. Ping it once.
    bool pinged = false;
    for (const auto& n : nets) {
        if (!n.gateway.empty() && n.gw_mac.empty()) {
            std::string ignored;
            run({"ping", "-c", "1", "-W", "1", "-I", n.iface, n.gateway}, ignored);
            pinged = true;
        }
    }
    if (pinged) {
        run({"ip", "neigh", "show"}, neigh);
        nets = parse_networks(addrs, routes, neigh);
    }
    return nets;
}

// `ufw status verbose` omits defaults while inactive; read them from /etc/default/ufw.
std::string defaults_line() {
    const auto text = read_file(kUfwDefaults);
    auto policy = [&text](const std::string& key, const char* fallback) -> std::string {
        const auto pos = text.find(key + "=\"");
        if (pos == std::string::npos) return fallback;
        const auto start = pos + key.size() + 2;
        const auto v = text.substr(start, text.find('"', start) - start);
        if (v == "DROP") return "deny";
        if (v == "REJECT") return "reject";
        if (v == "ACCEPT") return "allow";
        return fallback;
    };
    return "Default: " + policy("DEFAULT_INPUT_POLICY", "deny") + " (incoming), " +
           policy("DEFAULT_OUTPUT_POLICY", "allow") + " (outgoing), " +
           policy("DEFAULT_FORWARD_POLICY", "deny") + " (routed)";
}

// ------------------------------------------------------------------ My network sync

int sync_mynet() {
    const auto templates = parse_templates(read_file(kTemplates));
    const auto whitelist = parse_whitelist(read_file(kWhitelist));
    const auto rules4 = parse_rules_file(read_file(kUserRules), false);
    const auto rules6 = parse_rules_file(read_file(kUserRules6), true);
    const auto plan = plan_mynet_sync(templates, current_networks(), whitelist, rules4, rules6);
    int failures = 0;
    std::string out;
    for (const auto& args : plan.remove) {
        if (ufw(args, out) != 0) {
            std::fprintf(stderr, "sync: ufw %s failed: %s", join_args(args).c_str(), out.c_str());
            ++failures;
        }
    }
    for (const auto& args : plan.add) {
        if (ufw(args, out) != 0) {
            std::fprintf(stderr, "sync: ufw %s failed: %s", join_args(args).c_str(), out.c_str());
            ++failures;
        }
    }
    std::printf("sync: %zu removed, %zu added\n", plan.remove.size(), plan.add.size());
    return failures ? 1 : 0;
}

// ------------------------------------------------------------------ commands

std::string tuples_only(const std::string& text) {
    std::istringstream in(text);
    std::string line;
    std::string out;
    while (std::getline(in, line)) {
        if (line.rfind("### tuple ###", 0) == 0) out += line + "\n";
    }
    return out;
}

int cmd_state() {
    std::string out;
    ufw({"status", "verbose"}, out);
    std::printf("@status\n%s", out.c_str());
    if (out.find("Default:") == std::string::npos) {
        std::printf("%s\n", defaults_line().c_str());
    }
    std::printf("@rules4\n%s", tuples_only(read_file(kUserRules)).c_str());
    std::printf("@rules6\n%s", tuples_only(read_file(kUserRules6)).c_str());
    run({"ss", "-H", "-tulpn"}, out);
    std::printf("@sockets\n%s", out.c_str());
    run({"ip", "-o", "addr", "show", "up"}, out);
    std::printf("@addrs\n%s", out.c_str());
    run({"ip", "route", "show", "default"}, out);
    std::printf("@routes\n%s", out.c_str());
    run({"ip", "neigh", "show"}, out);
    std::printf("@neigh\n%s", out.c_str());
    std::printf("@whitelist\n%s", read_file(kWhitelist).c_str());
    std::printf("@templates\n%s", read_file(kTemplates).c_str());
    std::printf("@backups\n%zu\n", list_backups().size());
    return 0;
}

int cmd_add(const std::vector<std::string>& args) {
    const auto err = validate_rule_args(args);
    if (!err.empty()) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }
    const auto backup = make_backup();
    std::string out;
    const int code = ufw(args, out);
    std::fputs(out.c_str(), stdout);
    // ufw reports "Skipping adding existing rule" with exit 0; nothing changed then either
    if (code != 0 || out.find("Skipping") != std::string::npos) {
        drop_backup(backup);
    }
    return code;
}

int cmd_delete(const std::string& family, const std::string& tuple) {
    const auto rules4 = parse_rules_file(read_file(kUserRules), false);
    const auto rules6 = parse_rules_file(read_file(kUserRules6), true);
    const bool v6 = family == "6";
    const auto& list = v6 ? rules6 : rules4;
    for (size_t i = 0; i < list.size(); ++i) {
        if (list[i].raw != tuple) continue;
        if (list[i].is_mynet()) {
            std::fprintf(stderr, "error: My network rules are deleted with mynet-delete\n");
            return 2;
        }
        // ufw numbers IPv4 rules first, then IPv6
        const size_t number = (v6 ? rules4.size() : 0) + i + 1;
        const auto backup = make_backup();
        const int code = ufw_print({"--force", "delete", std::to_string(number)});
        if (code != 0) drop_backup(backup);
        return code;
    }
    std::fprintf(stderr, "error: rule not found (it may have changed); refresh and try again\n");
    return 3;
}

int cmd_mynet_add(const std::vector<std::string>& a) {
    if (a.size() < 4) {
        std::fprintf(stderr, "usage: mynet-add <action> <proto> <port> <whitelisted|any> [comment]\n");
        return 2;
    }
    Template t;
    t.action = a[0];
    t.proto = a[1];
    t.port = a[2];
    t.scope = a[3];
    for (size_t i = 4; i < a.size(); ++i) {
        t.comment += (i > 4 ? " " : "") + a[i];
    }
    if (!valid_action(t.action) || !valid_proto(t.proto) || !valid_port(t.port) ||
        !valid_scope(t.scope) || t.comment.find('\n') != std::string::npos) {
        std::fprintf(stderr, "error: invalid My network rule\n");
        return 2;
    }
    auto templates = parse_templates(read_file(kTemplates));
    int next = 1;
    for (const auto& x : templates) next = std::max(next, x.id + 1);
    t.id = next;
    make_backup();
    templates.push_back(t);
    if (!write_file(kTemplates, format_templates(templates))) {
        std::fprintf(stderr, "error: cannot write %s\n", kTemplates);
        return 1;
    }
    std::printf("added My network rule %d\n", t.id);
    return sync_mynet();
}

int cmd_mynet_delete(const std::string& id_text) {
    auto templates = parse_templates(read_file(kTemplates));
    const int id = std::atoi(id_text.c_str());
    const auto it = std::find_if(templates.begin(), templates.end(),
                                 [id](const Template& t) { return t.id == id; });
    if (it == templates.end()) {
        std::fprintf(stderr, "error: no My network rule %d\n", id);
        return 3;
    }
    make_backup();
    templates.erase(it);
    write_file(kTemplates, format_templates(templates));
    return sync_mynet();
}

int cmd_whitelist(bool add, const std::vector<std::string>& a) {
    if (a.size() < 2 || (a[0].rfind("gw:", 0) != 0 && a[0].rfind("if:", 0) != 0) ||
        !Cidr::parse(a[1]).valid) {
        std::fprintf(stderr, "usage: whitelist-add|whitelist-remove <gw:mac|if:iface> <subnet> [name]\n");
        return 2;
    }
    auto list = parse_whitelist(read_file(kWhitelist));
    list.erase(std::remove_if(list.begin(), list.end(),
                              [&](const WhitelistEntry& e) {
                                  return e.key == a[0] && e.subnet4 == a[1];
                              }),
               list.end());
    if (add) {
        WhitelistEntry e;
        e.key = a[0];
        e.subnet4 = a[1];
        for (size_t i = 2; i < a.size(); ++i) e.name += (i > 2 ? " " : "") + a[i];
        if (e.name.empty()) e.name = a[1];
        list.push_back(e);
    }
    if (!write_file(kWhitelist, format_whitelist(list))) {
        std::fprintf(stderr, "error: cannot write %s\n", kWhitelist);
        return 1;
    }
    return sync_mynet();
}

// Remove every live My network rule (templates stay). Used when uninstalling.
int cmd_clear_mynet() {
    const auto rules4 = parse_rules_file(read_file(kUserRules), false);
    const auto rules6 = parse_rules_file(read_file(kUserRules6), true);
    int failures = 0;
    std::string out;
    for (const auto* list : {&rules4, &rules6}) {
        for (const auto& r : *list) {
            if (!r.is_mynet()) continue;
            if (ufw(mynet_delete_args(r), out) != 0) ++failures;
        }
    }
    return failures ? 1 : 0;
}


// Everything state needs for the logic functions, read directly as root.
State read_state() {
    State st;
    std::string out;
    ufw({"status", "verbose"}, out);
    if (out.find("Default:") == std::string::npos) out += defaults_line() + "\n";
    st.status = parse_status_verbose(out);
    st.rules4 = parse_rules_file(read_file(kUserRules), false);
    st.rules6 = parse_rules_file(read_file(kUserRules6), true);
    run({"ss", "-H", "-tulpn"}, out);
    st.sockets = parse_ss(out);
    st.networks = current_networks();
    st.whitelist = parse_whitelist(read_file(kWhitelist));
    st.templates = parse_templates(read_file(kTemplates));
    st.ok = true;
    return st;
}

// SSH ports: what sshd listens on; if it is not running but is enabled, its configured
// port (sshd -T), else 22.
std::vector<int> ssh_ports(const State& st) {
    std::vector<int> ports;
    for (const auto& s : ssh_sockets(st.sockets)) {
        if (std::find(ports.begin(), ports.end(), s.port) == ports.end()) ports.push_back(s.port);
    }
    if (!ports.empty()) return ports;
    std::string out;
    const bool enabled = run({"systemctl", "is-enabled", "ssh"}, out) == 0 ||
                         run({"systemctl", "is-enabled", "sshd"}, out) == 0;
    if (!enabled) return ports;
    run({"sshd", "-T"}, out);
    std::istringstream in(out);
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("port ", 0) == 0) ports.push_back(std::atoi(line.c_str() + 5));
    }
    if (ports.empty()) ports.push_back(22);
    return ports;
}

// Add "limit <port>/tcp" for every SSH port the firewall would block once it is on.
int ssh_allow(bool make_backup_first) {
    const State st = read_state();
    Status on = st.status;
    on.active = true;
    const auto subnets = local_subnets(st.networks);
    std::vector<int> missing;
    for (const int port : ssh_ports(st)) {
        const bool v4 = verdict_reachable(evaluate(on, st.rules4, false, "tcp", port, "0.0.0.0", subnets));
        if (!v4) missing.push_back(port);
    }
    if (missing.empty()) return 0;
    if (make_backup_first) make_backup();
    int rc = 0;
    for (const int port : missing) {
        std::printf("allowing SSH: limit %d/tcp\n", port);
        if (ufw_print({"limit", std::to_string(port) + "/tcp", "comment", "ipdoit: SSH"}) != 0) rc = 1;
    }
    return rc;
}

int cmd_port_set(const std::vector<std::string>& a) {
    if (a.size() != 3 || !valid_port(a[0]) || a[0].find_first_of(":,") != std::string::npos ||
        !valid_proto(a[1]) || (a[2] != "blocked" && a[2] != "lan" && a[2] != "allowed")) {
        std::fprintf(stderr, "usage: port-set <port> <tcp|udp|any> <blocked|lan|allowed>\n");
        return 2;
    }
    const std::string port = a[0], proto = a[1], target = a[2];
    const State st = read_state();
    make_backup();
    int rc = 0;
    std::string out;
    // 1. remove "from anywhere" allow/limit rules for exactly this port/protocol
    std::set<std::string> actions;
    for (const auto* list : {&st.rules4, &st.rules6}) {
        for (const auto& r : *list) {
            if (r.forward || r.direction != "in" || r.dport != port || r.proto != proto ||
                !r.dapp.empty() || r.is_mynet() || !r.iface_in.empty() || r.sport != "any") continue;
            if (r.action != "allow" && r.action != "limit") continue;
            const Cidr src = Cidr::parse(r.src), dst = Cidr::parse(r.dst);
            if ((src.valid && !src.is_any()) || (dst.valid && !dst.is_any())) continue;
            actions.insert(r.action);
        }
    }
    const std::string spec = proto == "any" ? port : port + "/" + proto;
    for (const auto& act : actions) {
        if (ufw({"delete", act, spec}, out) != 0) {
            std::fprintf(stderr, "%s", out.c_str());
            rc = 1;
        }
    }
    // 2. remove LAN (whitelisted My network) templates for it
    auto templates = parse_templates(read_file(kTemplates));
    templates.erase(std::remove_if(templates.begin(), templates.end(),
                                   [&](const Template& t) {
                                       return (t.action == "allow" || t.action == "limit") &&
                                              t.port == port && t.proto == proto &&
                                              t.scope == "whitelisted";
                                   }),
                    templates.end());
    // 3. add the new state
    const std::string act = is_ssh_port(st, proto, std::atoi(port.c_str())) ? "limit" : "allow";
    if (target == "allowed") {
        if (ufw({act, spec}, out) != 0) {
            std::fprintf(stderr, "%s", out.c_str());
            rc = 1;
        }
    }
    else if (target == "lan") {
        Template t;
        int next = 1;
        for (const auto& x : templates) next = std::max(next, x.id + 1);
        t.id = next;
        t.action = act;
        t.proto = proto;
        t.port = port;
        t.scope = "whitelisted";
        templates.push_back(t);
    }
    if (!write_file(kTemplates, format_templates(templates))) {
        std::fprintf(stderr, "error: cannot write %s\n", kTemplates);
        return 1;
    }
    if (sync_mynet() != 0) rc = 1;
    std::printf("port %s/%s: %s\n", port.c_str(), proto.c_str(), target.c_str());
    return rc;
}

int cmd_undo() {
    const auto all = list_backups();
    if (all.empty()) {
        std::fprintf(stderr, "error: nothing to undo\n");
        return 3;
    }
    const auto dir = all.back();
    std::error_code ec;
    for (const char* f : {kUserRules, kUserRules6, kTemplates}) {
        const auto src = dir / fs::path(f).filename();
        if (fs::exists(src, ec)) {
            fs::copy_file(src, f, fs::copy_options::overwrite_existing, ec);
        }
        else if (std::string(f) == kTemplates) {
            fs::remove(f, ec); // no templates when the backup was made
        }
    }
    drop_backup(dir);
    std::string out;
    ufw({"status"}, out);
    if (out.find("Status: active") != std::string::npos) {
        if (ufw_print({"reload"}) != 0) return 1;
    }
    std::printf("restored rules from backup\n");
    return sync_mynet();
}

} // namespace

int main(int argc, char** argv) {
    if (::geteuid() != 0) {
        std::fprintf(stderr, "ipdoit-helper must run as root\n");
        return 1;
    }
    ::umask(022);
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        std::fprintf(stderr, "usage: ipdoit-helper <command> [args]\n");
        return 2;
    }
    const std::string cmd = args[0];
    args.erase(args.begin());

    if (cmd == "state") return cmd_state();
    if (cmd == "dry-run") {
        const auto err = validate_rule_args(args);
        if (!err.empty()) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 2;
        }
        args.insert(args.begin(), "--dry-run");
        return ufw_print(args);
    }

    std::error_code ec;
    fs::create_directories(kEtcDir, ec);
    Lock lock;
    if (!lock.held()) {
        std::fprintf(stderr, "error: another firewall change is in progress\n");
        return 4;
    }
    if (cmd == "enable") {
        ssh_allow(true); // SSH exception: never lock out an enabled sshd
        return ufw_print({"--force", "enable"});
    }
    if (cmd == "disable") return ufw_print({"disable"});
    if (cmd == "add") return cmd_add(args);
    if (cmd == "delete" && args.size() == 2) return cmd_delete(args[0], args[1]);
    if (cmd == "mynet-add") return cmd_mynet_add(args);
    if (cmd == "mynet-delete" && args.size() == 1) return cmd_mynet_delete(args[0]);
    if (cmd == "whitelist-add") return cmd_whitelist(true, args);
    if (cmd == "whitelist-remove") return cmd_whitelist(false, args);
    if (cmd == "undo") return cmd_undo();
    if (cmd == "sync") return sync_mynet();
    if (cmd == "clear-mynet") return cmd_clear_mynet();
    if (cmd == "port-set") return cmd_port_set(args);
    if (cmd == "ssh-allow") return ssh_allow(true);
    std::fprintf(stderr, "unknown command: %s\n", cmd.c_str());
    return 2;
}
