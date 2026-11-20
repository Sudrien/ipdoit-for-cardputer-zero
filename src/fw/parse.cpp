/*
 * SPDX-License-Identifier: MIT
 */

#include "parse.h"

#include <cctype>
#include <cstdlib>
#include <map>
#include <sstream>

namespace fw {
namespace {

std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream in(s);
    std::string w;
    while (in >> w) {
        out.push_back(w);
    }
    return out;
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.rfind(p, 0) == 0;
}

std::string trim(const std::string& s) {
    size_t a = 0;
    size_t b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) {
        ++a;
    }
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) {
        --b;
    }
    return s.substr(a, b - a);
}

bool all_digits(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

bool valid_port_number(const std::string& s) {
    if (!all_digits(s) || s.size() > 5) {
        return false;
    }
    const int v = std::atoi(s.c_str());
    return v >= 1 && v <= 65535;
}

} // namespace

// ------------------------------------------------------------------ hex

std::string hex_encode(const std::string& s) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    for (unsigned char c : s) {
        out += digits[c >> 4];
        out += digits[c & 15];
    }
    return out;
}

std::string hex_decode(const std::string& hex) {
    std::string out;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = val(hex[i]);
        const int lo = val(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return {};
        }
        out += static_cast<char>((hi << 4) | lo);
    }
    return out;
}

// ------------------------------------------------------------------ rules

bool Rule::is_mynet() const {
    return mynet_id() >= 0;
}

int Rule::mynet_id() const {
    static const std::string tag = "ipdoit:mynet:";
    if (!starts_with(comment, tag)) {
        return -1;
    }
    const auto rest = comment.substr(tag.size());
    const auto end = rest.find_first_not_of("0123456789");
    const auto digits = rest.substr(0, end);
    return all_digits(digits) ? std::atoi(digits.c_str()) : -1;
}

bool Rule::port_matches(int port) const {
    if (dport == "any") {
        return true;
    }
    std::istringstream in(dport);
    std::string part;
    while (std::getline(in, part, ',')) {
        const auto colon = part.find(':');
        if (colon == std::string::npos) {
            if (std::atoi(part.c_str()) == port) {
                return true;
            }
        }
        else {
            const int lo = std::atoi(part.substr(0, colon).c_str());
            const int hi = std::atoi(part.substr(colon + 1).c_str());
            if (port >= lo && port <= hi) {
                return true;
            }
        }
    }
    return false;
}

bool parse_tuple(const std::string& line_in, bool v6, Rule& out) {
    std::string line = trim(line_in);
    static const std::string prefix = "### tuple ###";
    if (starts_with(line, prefix)) {
        line = trim(line.substr(prefix.size()));
    }
    Rule r;
    r.v6 = v6;
    r.raw = line;
    // comment= is always last
    const auto cpos = line.find(" comment=");
    if (cpos != std::string::npos) {
        r.comment = hex_decode(trim(line.substr(cpos + 9)));
        line = line.substr(0, cpos);
    }
    const auto f = split_ws(line);
    if (f.size() < 6 || f.size() > 9) {
        return false;
    }
    std::string action = f[0];
    if (starts_with(action, "route:")) {
        r.forward = true;
        action = action.substr(6);
    }
    const auto us = action.find('_');
    if (us != std::string::npos) {
        r.log = true;
        action = action.substr(0, us);
    }
    r.action = action;
    r.proto = f[1];
    r.dport = f[2];
    r.dst = f[3];
    r.sport = f[4];
    r.src = f[5];
    r.direction = "in";
    if (f.size() >= 8) {
        auto unescape = [](std::string s) {
            std::string o;
            for (size_t i = 0; i < s.size(); ++i) {
                if (s.compare(i, 3, "%20") == 0) {
                    o += ' ';
                    i += 2;
                }
                else {
                    o += s[i];
                }
            }
            return o;
        };
        if (f[6] != "-") r.dapp = unescape(f[6]);
        if (f[7] != "-") r.sapp = unescape(f[7]);
    }
    if (f.size() == 7 || f.size() == 9) {
        const auto& d = f.back();
        const auto bang = d.find('!');
        if (bang != std::string::npos) {
            r.iface_in = d.substr(0, bang).substr(3);
            r.iface_out = d.substr(bang + 1).substr(4);
            r.direction = "in";
        }
        else if (starts_with(d, "in_")) {
            r.direction = "in";
            r.iface_in = d.substr(3);
        }
        else if (starts_with(d, "out_")) {
            r.direction = "out";
            r.iface_out = d.substr(4);
        }
        else {
            r.direction = d;
        }
    }
    out = std::move(r);
    return true;
}

std::vector<Rule> parse_rules_file(const std::string& text, bool v6) {
    std::vector<Rule> rules;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (!starts_with(trim(line), "### tuple ###")) {
            continue;
        }
        Rule r;
        if (parse_tuple(line, v6, r)) {
            rules.push_back(std::move(r));
        }
    }
    return rules;
}

void parse_dry_run(const std::string& text, std::vector<Rule>& v4, std::vector<Rule>& v6) {
    v4.clear();
    v6.clear();
    std::istringstream in(text);
    std::string line;
    bool in_v6 = false;
    while (std::getline(in, line)) {
        const auto t = trim(line);
        if (starts_with(t, ":ufw6-")) {
            in_v6 = true;
        }
        else if (starts_with(t, ":ufw-")) {
            in_v6 = false;
        }
        if (!starts_with(t, "### tuple ###")) {
            continue;
        }
        Rule r;
        if (parse_tuple(t, in_v6, r)) {
            (in_v6 ? v6 : v4).push_back(std::move(r));
        }
    }
}

// ------------------------------------------------------------------ ss

std::vector<Socket> parse_ss(const std::string& text) {
    std::vector<Socket> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        const auto f = split_ws(line);
        // Netid State Recv-Q Send-Q Local:Port Peer:Port [Process]
        if (f.size() < 6 || (f[0] != "tcp" && f[0] != "udp")) {
            continue;
        }
        Socket s;
        s.proto = f[0];
        std::string local = f[4];
        const auto colon = local.rfind(':');
        if (colon == std::string::npos) {
            continue;
        }
        const auto port = local.substr(colon + 1);
        if (!all_digits(port)) {
            continue;
        }
        s.port = std::atoi(port.c_str());
        std::string addr = local.substr(0, colon);
        if (addr.size() >= 2 && addr.front() == '[' && addr.back() == ']') {
            addr = addr.substr(1, addr.size() - 2);
        }
        const auto pct = addr.find('%');
        if (pct != std::string::npos) {
            addr = addr.substr(0, pct);
        }
        s.address = addr;
        const auto users = line.find("users:((\"");
        if (users != std::string::npos) {
            const auto start = users + 9;
            const auto end = line.find('"', start);
            if (end != std::string::npos) {
                s.process = line.substr(start, end - start);
            }
        }
        out.push_back(std::move(s));
    }
    return out;
}

// ------------------------------------------------------------------ ip

std::vector<Network> parse_networks(const std::string& addrs, const std::string& routes,
                                    const std::string& neigh) {
    std::vector<Network> nets;
    auto find_net = [&nets](const std::string& iface) -> Network& {
        for (auto& n : nets) {
            if (n.iface == iface) {
                return n;
            }
        }
        nets.push_back(Network{});
        nets.back().iface = iface;
        return nets.back();
    };

    std::istringstream in(addrs);
    std::string line;
    while (std::getline(in, line)) {
        // "4: wlan0    inet 192.168.1.23/24 brd ... scope global dynamic wlan0\ ..."
        const auto f = split_ws(line);
        if (f.size() < 4) {
            continue;
        }
        std::string iface = f[1];
        const auto at = iface.find('@');
        if (at != std::string::npos) {
            iface = iface.substr(0, at);
        }
        if (iface == "lo") {
            continue;
        }
        const bool v4 = f[2] == "inet";
        const bool v6 = f[2] == "inet6";
        if (!v4 && !v6) {
            continue;
        }
        bool global = false;
        for (size_t i = 3; i + 1 < f.size(); ++i) {
            if (f[i] == "scope") {
                global = f[i + 1] == "global";
            }
        }
        const Cidr c = Cidr::parse(f[3]);
        if (!c.valid || !global || c.is_loopback() || c.is_link_local()) {
            continue;
        }
        auto& n = find_net(iface);
        if (v4 && n.subnet4.empty()) {
            n.subnet4 = c.network().str();
        }
        if (v6 && n.subnet6.empty()) {
            n.subnet6 = c.network().str();
        }
    }

    std::istringstream rin(routes);
    while (std::getline(rin, line)) {
        // "default via 192.168.1.1 dev wlan0 proto dhcp ..."
        const auto f = split_ws(line);
        std::string via;
        std::string dev;
        for (size_t i = 0; i + 1 < f.size(); ++i) {
            if (f[i] == "via") via = f[i + 1];
            if (f[i] == "dev") dev = f[i + 1];
        }
        if (via.empty() || dev.empty() || Cidr::parse(via).v6) {
            continue;
        }
        for (auto& n : nets) {
            if (n.iface == dev && n.gateway.empty()) {
                n.gateway = via;
            }
        }
    }

    std::istringstream nin(neigh);
    while (std::getline(nin, line)) {
        // "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        const auto f = split_ws(line);
        std::string dev;
        std::string mac;
        for (size_t i = 1; i + 1 < f.size(); ++i) {
            if (f[i] == "dev") dev = f[i + 1];
            if (f[i] == "lladdr") mac = f[i + 1];
        }
        if (f.empty() || mac.empty()) {
            continue;
        }
        for (auto& n : nets) {
            if (n.iface == dev && n.gateway == f[0]) {
                n.gw_mac = mac;
            }
        }
    }

    // drop interfaces with neither a v4 nor a v6 network
    std::vector<Network> out;
    for (auto& n : nets) {
        if (!n.subnet4.empty() || !n.subnet6.empty()) {
            out.push_back(std::move(n));
        }
    }
    return out;
}

// ------------------------------------------------------------------ ufw status

Status parse_status_verbose(const std::string& text) {
    Status st;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (starts_with(line, "Status:")) {
            st.active = trim(line.substr(7)) == "active";
        }
        else if (starts_with(line, "Default:")) {
            // "Default: deny (incoming), allow (outgoing), disabled (routed)"
            std::istringstream parts(line.substr(8));
            std::string part;
            while (std::getline(parts, part, ',')) {
                const auto w = split_ws(part);
                if (w.size() < 2) continue;
                if (w[1] == "(incoming)") st.default_in = w[0];
                else if (w[1] == "(outgoing)") st.default_out = w[0];
                else if (w[1] == "(routed)") st.default_routed = w[0];
            }
        }
    }
    return st;
}

// ------------------------------------------------------------------ config files

bool valid_action(const std::string& s) {
    return s == "allow" || s == "deny" || s == "reject" || s == "limit";
}

bool valid_proto(const std::string& s) {
    return s == "tcp" || s == "udp" || s == "any";
}

bool valid_port(const std::string& s) {
    if (s.empty()) {
        return false;
    }
    std::istringstream in(s);
    std::string part;
    int count = 0;
    while (std::getline(in, part, ',')) {
        ++count;
        const auto colon = part.find(':');
        if (colon == std::string::npos) {
            if (!valid_port_number(part)) return false;
        }
        else {
            const auto lo = part.substr(0, colon);
            const auto hi = part.substr(colon + 1);
            if (!valid_port_number(lo) || !valid_port_number(hi) ||
                std::atoi(lo.c_str()) >= std::atoi(hi.c_str())) {
                return false;
            }
        }
    }
    return count >= 1 && count <= 15 && s.back() != ',';
}

bool valid_scope(const std::string& s) {
    return s == "whitelisted" || s == "any";
}

std::vector<WhitelistEntry> parse_whitelist(const std::string& text) {
    std::vector<WhitelistEntry> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        std::istringstream f(line);
        WhitelistEntry e;
        f >> e.key >> e.subnet4;
        std::getline(f, e.name);
        e.name = trim(e.name);
        if ((starts_with(e.key, "gw:") || starts_with(e.key, "if:")) &&
            Cidr::parse(e.subnet4).valid) {
            out.push_back(std::move(e));
        }
    }
    return out;
}

std::string format_whitelist(const std::vector<WhitelistEntry>& entries) {
    std::string out = "# Ipdoit network whitelist: <gw:mac|if:iface> <subnet> <name>\n";
    for (const auto& e : entries) {
        out += e.key + " " + e.subnet4 + " " + e.name + "\n";
    }
    return out;
}

std::vector<Template> parse_templates(const std::string& text) {
    std::vector<Template> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        const auto f = split_ws(line);
        if (f.size() != 6 || !all_digits(f[0])) continue;
        Template t;
        t.id = std::atoi(f[0].c_str());
        t.action = f[1];
        t.proto = f[2];
        t.port = f[3];
        t.scope = f[4];
        t.comment = f[5] == "-" ? "" : hex_decode(f[5]);
        if (valid_action(t.action) && valid_proto(t.proto) && valid_port(t.port) &&
            valid_scope(t.scope)) {
            out.push_back(std::move(t));
        }
    }
    return out;
}

std::string format_templates(const std::vector<Template>& templates) {
    std::string out =
        "# Ipdoit My network rules: <id> <action> <proto> <port> <scope> <comment-hex>\n";
    for (const auto& t : templates) {
        out += std::to_string(t.id) + " " + t.action + " " + t.proto + " " + t.port + " " +
               t.scope + " " + (t.comment.empty() ? "-" : hex_encode(t.comment)) + "\n";
    }
    return out;
}

// ------------------------------------------------------------------ helper state

State parse_state(const std::string& text) {
    State st;
    std::map<std::string, std::string> sections;
    std::string current;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (starts_with(line, "@")) {
            current = trim(line.substr(1));
            sections[current];
            continue;
        }
        if (!current.empty()) {
            sections[current] += line + "\n";
        }
    }
    if (!sections.count("status")) {
        st.error = text.empty() ? "no output from ipdoit-helper" : trim(text);
        return st;
    }
    st.status = parse_status_verbose(sections["status"]);
    st.rules4 = parse_rules_file(sections["rules4"], false);
    st.rules6 = parse_rules_file(sections["rules6"], true);
    st.sockets = parse_ss(sections["sockets"]);
    st.networks = parse_networks(sections["addrs"], sections["routes"], sections["neigh"]);
    st.whitelist = parse_whitelist(sections["whitelist"]);
    st.templates = parse_templates(sections["templates"]);
    st.backups = std::atoi(trim(sections["backups"]).c_str());
    st.nm_hook = sections.count("nmhook") ? std::atoi(trim(sections["nmhook"]).c_str()) : -1;
    st.ok = true;
    return st;
}

} // namespace fw
