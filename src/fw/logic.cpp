/*
 * SPDX-License-Identifier: MIT
 */

#include "logic.h"

#include "net.h"
#include "parse.h"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <set>
#include <sstream>

namespace fw {
namespace {

bool all_digits(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

bool proto_matches(const std::string& rule_proto, const std::string& proto) {
    return rule_proto == "any" || rule_proto == proto;
}

bool is_wildcard_address(const std::string& addr) {
    return addr == "*" || addr == "0.0.0.0" || addr == "::";
}

} // namespace

// ================================================================ verdicts

const char* verdict_label(Verdict v) {
    switch (v) {
        case Verdict::NotApplicable: return "-";
        case Verdict::FirewallOff: return "Firewall off";
        case Verdict::LocalOnly: return "Local only";
        case Verdict::Allowed: return "Allowed";
        case Verdict::Limited: return "Limited";
        case Verdict::LanOnly: return "LAN only";
        case Verdict::Partial: return "Partial";
        case Verdict::Blocked: return "Blocked";
    }
    return "";
}

bool verdict_reachable(Verdict v) {
    return v != Verdict::Blocked && v != Verdict::NotApplicable && v != Verdict::LocalOnly;
}

Verdict evaluate(const Status& status, const std::vector<Rule>& rules, bool v6,
                 const std::string& proto, int port, const std::string& address,
                 const std::vector<std::string>& local_subnets) {
    const Cidr bound = Cidr::parse(address == "*" ? (v6 ? "::" : "0.0.0.0") : address);
    if (bound.valid && bound.is_loopback()) {
        return Verdict::LocalOnly;
    }
    if (!status.active) {
        return Verdict::FirewallOff;
    }
    const bool wildcard = is_wildcard_address(address);

    bool partial = false;
    bool partial_all_local = true;
    std::string final_action;

    for (const auto& r : rules) {
        if (r.forward || r.direction != "in" || r.v6 != v6) {
            continue;
        }
        if (!proto_matches(r.proto, proto) || !r.port_matches(port)) {
            continue;
        }
        // Destination: a rule for one address only covers a wildcard socket partly.
        const Cidr dst = Cidr::parse(r.dst);
        bool restricted = false;
        if (dst.valid && !dst.is_any()) {
            if (wildcard) {
                restricted = true;
            }
            else if (!dst.contains(bound)) {
                continue;
            }
        }
        if (!r.iface_in.empty() || r.sport != "any") {
            restricted = true;
        }
        const Cidr src = Cidr::parse(r.src);
        const bool src_any = !src.valid || src.is_any();
        if (src_any && !restricted) {
            final_action = r.action; // first full match wins
            break;
        }
        if (r.action == "allow" || r.action == "limit") {
            partial = true;
            bool local = false;
            if (!restricted && src.valid) {
                for (const auto& s : local_subnets) {
                    const Cidr net = Cidr::parse(s);
                    if (net.valid && net.contains(src) && src.contains(net)) {
                        local = true;
                    }
                }
            }
            partial_all_local = partial_all_local && local;
        }
    }

    if (final_action.empty()) {
        final_action = status.default_in; // deny / reject / allow
    }
    if (final_action == "allow") return Verdict::Allowed;
    if (final_action == "limit") return Verdict::Limited;
    if (partial) {
        return partial_all_local ? Verdict::LanOnly : Verdict::Partial;
    }
    return Verdict::Blocked;
}

std::string PortRow::summary() const {
    if (v6 == Verdict::NotApplicable) return verdict_label(v4);
    if (v4 == Verdict::NotApplicable || v4 == v6) return verdict_label(v6);
    return std::string("v4 ") + verdict_label(v4) + ", v6 " + verdict_label(v6);
}

std::vector<PortRow> port_rows(const State& state) {
    return port_rows(state, state.status, state.rules4, state.rules6);
}

std::vector<PortRow> port_rows(const State& state, const Status& status,
                               const std::vector<Rule>& rules4,
                               const std::vector<Rule>& rules6) {
    const auto subnets = local_subnets(state.networks);
    std::map<std::string, PortRow> rows; // key proto/port/process
    std::vector<std::string> order;
    for (const auto& s : state.sockets) {
        const std::string key = s.proto + "/" + std::to_string(s.port) + "/" + s.process;
        if (!rows.count(key)) {
            PortRow row;
            row.proto = s.proto;
            row.port = s.port;
            row.process = s.process;
            rows[key] = row;
            order.push_back(key);
        }
        auto& row = rows[key];
        const Cidr a = Cidr::parse(s.address == "*" ? "::" : s.address);
        const bool v6_sock = s.address == "*" || (a.valid && a.v6);
        const bool v4_sock = s.address == "*" || (a.valid && !a.v6);
        const std::string bind = is_wildcard_address(s.address) ? "all" : s.address;
        if (row.bind.empty() || row.bind == bind) {
            row.bind = bind;
        }
        else if (bind == "all") {
            row.bind = "all";
        }
        auto merge = [](Verdict& slot, Verdict v) {
            // keep the most reachable verdict among sockets of this row
            if (slot == Verdict::NotApplicable || slot == Verdict::LocalOnly ||
                (slot == Verdict::Blocked && v != Verdict::LocalOnly)) {
                slot = v;
            }
        };
        if (v4_sock) {
            merge(row.v4, evaluate(status, rules4, false, s.proto, s.port,
                                   s.address == "*" ? "0.0.0.0" : s.address, subnets));
        }
        if (v6_sock) {
            merge(row.v6, evaluate(status, rules6, true, s.proto, s.port,
                                   s.address == "*" ? "::" : s.address, subnets));
        }
    }
    std::vector<PortRow> out;
    for (const auto& k : order) {
        out.push_back(rows[k]);
    }
    std::sort(out.begin(), out.end(), [](const PortRow& a, const PortRow& b) {
        if (a.port != b.port) return a.port < b.port;
        return a.proto < b.proto;
    });
    return out;
}

// ================================================================ networks

bool is_whitelisted(const Network& net, const std::vector<WhitelistEntry>& whitelist) {
    for (const auto& e : whitelist) {
        if (e.key == net.key() && e.subnet4 == net.subnet4) {
            return true;
        }
    }
    return false;
}

const Network* primary_network(const std::vector<Network>& nets) {
    for (const auto& n : nets) {
        if (!n.gateway.empty()) return &n;
    }
    return nets.empty() ? nullptr : &nets.front();
}

std::vector<std::string> local_subnets(const std::vector<Network>& nets) {
    std::vector<std::string> out;
    for (const auto& n : nets) {
        if (!n.subnet4.empty()) out.push_back(n.subnet4);
        if (!n.subnet6.empty()) out.push_back(n.subnet6);
    }
    return out;
}

// ================================================================ My network sync

std::vector<std::string> mynet_rule_args(const Template& t, const std::string& subnet) {
    std::vector<std::string> args = {t.action};
    if (t.proto != "any") {
        args.insert(args.end(), {"proto", t.proto});
    }
    args.insert(args.end(), {"from", subnet, "to", "any", "port", t.port});
    std::string comment = "ipdoit:mynet:" + std::to_string(t.id);
    if (!t.comment.empty()) {
        comment += " " + t.comment;
    }
    args.insert(args.end(), {"comment", comment});
    return args;
}

std::vector<std::string> mynet_delete_args(const Rule& live) {
    std::vector<std::string> args = {"delete", live.action};
    if (live.proto != "any") {
        args.insert(args.end(), {"proto", live.proto});
    }
    args.insert(args.end(), {"from", live.src, "to", "any", "port", live.dport});
    return args;
}

SyncPlan plan_mynet_sync(const std::vector<Template>& templates,
                         const std::vector<Network>& networks,
                         const std::vector<WhitelistEntry>& whitelist,
                         const std::vector<Rule>& rules4, const std::vector<Rule>& rules6) {
    // desired: (template id, subnet) -> template
    std::map<std::pair<int, std::string>, const Template*> desired;
    // A network whose gateway MAC is not known yet (just connected, neighbour table
    // empty) cannot be checked against the whitelist. Keep whatever whitelisted-only
    // rules it already has, add none, and let the next sync decide.
    std::map<std::pair<int, std::string>, const Template*> keep_if_present;
    for (const auto& t : templates) {
        for (const auto& n : networks) {
            const bool uncertain = !n.gateway.empty() && n.gw_mac.empty();
            if (t.scope == "whitelisted" && uncertain) {
                for (const auto& subnet : {n.subnet4, n.subnet6}) {
                    if (!subnet.empty()) keep_if_present[{t.id, subnet}] = &t;
                }
                continue;
            }
            if (t.scope == "whitelisted" && !is_whitelisted(n, whitelist)) {
                continue;
            }
            for (const auto& subnet : {n.subnet4, n.subnet6}) {
                if (!subnet.empty()) {
                    desired[{t.id, subnet}] = &t;
                }
            }
        }
    }

    SyncPlan plan;
    std::set<std::pair<int, std::string>> present;
    auto check = [&](const Rule& r) {
        const int id = r.mynet_id();
        if (id < 0) return;
        const auto key = std::make_pair(id, r.src);
        const Template* want = nullptr;
        if (const auto it = desired.find(key); it != desired.end()) {
            want = it->second;
        }
        else if (const auto kt = keep_if_present.find(key); kt != keep_if_present.end()) {
            want = kt->second;
        }
        // stale when not wanted, or when the template changed (action/proto/port)
        const bool stale = !want || want->action != r.action || want->proto != r.proto ||
                           want->port != r.dport || present.count(key);
        if (stale) {
            plan.remove.push_back(mynet_delete_args(r));
        }
        else {
            present.insert(key);
        }
    };
    for (const auto& r : rules4) check(r);
    for (const auto& r : rules6) check(r);

    for (const auto& [key, t] : desired) {
        if (!present.count(key)) {
            plan.add.push_back(mynet_rule_args(*t, key.second));
        }
    }
    return plan;
}

// ================================================================ user rules

std::string validate_rule_args(const std::vector<std::string>& args) {
    if (args.empty()) {
        return "empty rule";
    }
    size_t i = 0;
    if (args[0] == "insert" || args[0] == "prepend") {
        if (args[0] == "insert") {
            if (args.size() < 2 || !all_digits(args[1])) {
                return "insert needs a rule number";
            }
            i = 2;
        }
        else {
            i = 1;
        }
    }
    if (i >= args.size() || !valid_action(args[i])) {
        return "only allow, deny, reject and limit rules can be added here";
    }
    for (const auto& a : args) {
        if (a.empty() || a[0] == '-') {
            return "options starting with '-' are not allowed";
        }
        for (const char c : a) {
            if (static_cast<unsigned char>(c) < 0x20) {
                return "control characters are not allowed";
            }
        }
    }
    return "";
}

std::string validate_freeform(const std::string& text, std::vector<std::string>& args) {
    args.clear();
    // Split on spaces; a quoted part ('...' or "...") may contain spaces (for comments).
    std::string cur;
    char quote = 0;
    bool has = false;
    for (const char c : text) {
        if (quote) {
            if (c == quote) {
                quote = 0;
            }
            else {
                cur += c;
            }
        }
        else if (c == '\'' || c == '"') {
            quote = c;
            has = true;
        }
        else if (c == ' ' || c == '\t') {
            if (has || !cur.empty()) {
                args.push_back(cur);
            }
            cur.clear();
            has = false;
        }
        else {
            cur += c;
        }
    }
    if (quote) {
        return "unterminated quote";
    }
    if (has || !cur.empty()) {
        args.push_back(cur);
    }
    if (!args.empty() && args[0] == "ufw") {
        args.erase(args.begin());
    }
    return validate_rule_args(args);
}

std::string validate_form(const RuleForm& f) {
    if (!valid_action(f.action)) return "pick an action";
    if (f.direction != "in" && f.direction != "out") return "pick a direction";
    if (!valid_port(f.port)) return "port must be 1-65535, a range like 6000:6007, or a list";
    if (!valid_proto(f.proto)) return "pick a protocol";
    if ((f.port.find(':') != std::string::npos || f.port.find(',') != std::string::npos) &&
        f.proto == "any") {
        return "port ranges and lists need tcp or udp";
    }
    if (f.source == RuleForm::Source::Custom) {
        const Cidr c = Cidr::parse(f.custom_source);
        if (!c.valid) return "source must be an IP address or CIDR, like 192.168.1.0/24";
    }
    if (f.is_mynet() && f.direction != "in") return "My network rules are incoming only";
    if (f.comment.find('\'') != std::string::npos || f.comment.size() > 60) {
        return "comment: up to 60 characters, no quotes";
    }
    return "";
}

std::vector<std::string> form_args(const RuleForm& f) {
    std::vector<std::string> args = {f.action};
    if (f.direction == "out") {
        args.push_back("out");
    }
    if (f.proto != "any") {
        args.insert(args.end(), {"proto", f.proto});
    }
    const std::string from = f.source == RuleForm::Source::Custom ? f.custom_source : "any";
    if (f.direction == "out") {
        args.insert(args.end(), {"to", from == "any" ? "any" : from, "port", f.port});
    }
    else {
        args.insert(args.end(), {"from", from, "to", "any", "port", f.port});
    }
    if (!f.comment.empty()) {
        args.insert(args.end(), {"comment", f.comment});
    }
    return args;
}

Template form_template(const RuleForm& f) {
    Template t;
    t.action = f.action;
    t.proto = f.proto;
    t.port = f.port;
    t.scope = f.source == RuleForm::Source::MyNetAny ? "any" : "whitelisted";
    t.comment = f.comment;
    return t;
}

const std::vector<Preset>& presets() {
    static const std::vector<Preset> list = {
        {"SSH", "limit", "22", "tcp"},
        {"HTTP", "allow", "80", "tcp"},
        {"HTTPS", "allow", "443", "tcp"},
        {"DNS", "allow", "53", "any"},
        {"mDNS", "allow", "5353", "udp"},
    };
    return list;
}

std::string join_args(const std::vector<std::string>& args) {
    std::string out;
    for (const auto& a : args) {
        if (!out.empty()) out += ' ';
        if (a.find(' ') != std::string::npos) {
            out += "'" + a + "'";
        }
        else {
            out += a;
        }
    }
    return out;
}

std::string describe_rule(const Rule& r) {
    std::string action = r.action;
    std::transform(action.begin(), action.end(), action.begin(), ::toupper);
    std::string s = action + " ";
    if (r.direction == "out") s += "out ";
    if (!r.dapp.empty()) {
        s += r.dapp;
    }
    else {
        s += r.dport == "any" ? std::string("all") : r.dport;
        if (r.proto != "any") s += "/" + r.proto;
    }
    const Cidr src = Cidr::parse(r.src);
    s += " from " + ((!src.valid || src.is_any()) ? std::string("any") : r.src);
    if (!r.iface_in.empty()) s += " on " + r.iface_in;
    if (!r.iface_out.empty()) s += " on " + r.iface_out;
    if (r.v6) s += " (v6)";
    if (!r.comment.empty() && !r.is_mynet()) s += "  # " + r.comment;
    return s;
}

std::string describe_template(const Template& t) {
    std::string action = t.action;
    std::transform(action.begin(), action.end(), action.begin(), ::toupper);
    std::string s = action + " " + t.port;
    if (t.proto != "any") s += "/" + t.proto;
    s += t.scope == "any" ? " from My network" : " from My network (whitelisted)";
    if (!t.comment.empty()) s += "  # " + t.comment;
    return s;
}

// ================================================================ SSH guard

std::vector<Socket> ssh_sockets(const std::vector<Socket>& sockets) {
    std::vector<Socket> out;
    for (const auto& s : sockets) {
        if (s.proto != "tcp" || s.process != "sshd") continue;
        const Cidr a = Cidr::parse(s.address == "*" ? "::" : s.address);
        if (a.valid && a.is_loopback()) continue;
        out.push_back(s);
    }
    return out;
}

std::string ssh_guard(const State& state, const Status& after_status,
                      const std::vector<Rule>& after4, const std::vector<Rule>& after6) {
    const auto socks = ssh_sockets(state.sockets);
    if (socks.empty()) {
        return "";
    }
    const auto subnets = local_subnets(state.networks);
    std::set<int> blocked_ports;
    for (const auto& s : socks) {
        for (const bool v6 : {false, true}) {
            const Cidr a = Cidr::parse(s.address == "*" ? "::" : s.address);
            const bool applies = s.address == "*" || (a.valid && a.v6 == v6);
            if (!applies) continue;
            const std::string addr = s.address == "*" ? (v6 ? "::" : "0.0.0.0") : s.address;
            const auto& before_rules = v6 ? state.rules6 : state.rules4;
            const auto& after_rules = v6 ? after6 : after4;
            const Verdict before =
                evaluate(state.status, before_rules, v6, "tcp", s.port, addr, subnets);
            const Verdict after =
                evaluate(after_status, after_rules, v6, "tcp", s.port, addr, subnets);
            if (verdict_reachable(before) && !verdict_reachable(after)) {
                blocked_ports.insert(s.port);
            }
        }
    }
    if (blocked_ports.empty()) {
        return "";
    }
    std::string ports;
    for (const int p : blocked_ports) {
        if (!ports.empty()) ports += ", ";
        ports += std::to_string(p);
    }
    return "This blocks SSH (port " + ports + "). If you are connected over SSH, you will be "
           "locked out.";
}

} // namespace fw
