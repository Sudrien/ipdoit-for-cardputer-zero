/*
 * SPDX-License-Identifier: MIT
 */

// Self-contained tests for the firewall parsers and logic (no LVGL, no root).

#include "logic.h"
#include "net.h"
#include "parse.h"

#include <cstdio>
#include <string>

namespace {
int failures = 0;

#define CHECK(cond)                                                                      \
    do {                                                                                 \
        if (!(cond)) {                                                                   \
            std::fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                                  \
        }                                                                                \
    } while (0)

using namespace fw;

void test_cidr() {
    const auto net = Cidr::parse("192.168.1.0/24");
    CHECK(net.valid && !net.v6 && net.prefix == 24);
    CHECK(net.contains(Cidr::parse("192.168.1.77")));
    CHECK(!net.contains(Cidr::parse("192.168.2.1")));
    CHECK(Cidr::parse("192.168.1.23/24").network().str() == "192.168.1.0/24");
    CHECK(Cidr::parse("0.0.0.0/0").is_any());
    CHECK(Cidr::parse("127.0.0.53").is_loopback());
    CHECK(Cidr::parse("::1").is_loopback());
    CHECK(Cidr::parse("fe80::1%wlan0").is_link_local());
    CHECK(Cidr::parse("2001:db8:1:2::5/64").network().str() == "2001:db8:1:2::/64");
    CHECK(!Cidr::parse("192.168.1.0/33").valid);
    CHECK(!Cidr::parse("not-an-ip").valid);
}

void test_tuples() {
    Rule r;
    CHECK(parse_tuple("### tuple ### allow tcp 8080 0.0.0.0/0 any 192.168.1.0/24 in comment=776562206c616e", false, r));
    CHECK(r.action == "allow" && r.proto == "tcp" && r.dport == "8080");
    CHECK(r.src == "192.168.1.0/24" && r.direction == "in" && r.comment == "web lan");
    CHECK(r.raw == "allow tcp 8080 0.0.0.0/0 any 192.168.1.0/24 in comment=776562206c616e");

    CHECK(parse_tuple("limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in_wlan0", false, r));
    CHECK(r.action == "limit" && r.iface_in == "wlan0" && r.direction == "in");

    CHECK(parse_tuple("allow_log tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in", false, r));
    CHECK(r.action == "allow" && r.log && r.dapp == "OpenSSH");

    CHECK(parse_tuple("route:allow any any 10.0.0.0/8 any 0.0.0.0/0 in_eth0!out_wlan0", false, r));
    CHECK(r.forward && r.iface_in == "eth0" && r.iface_out == "wlan0");

    CHECK(parse_tuple("deny tcp 25 0.0.0.0/0 any 0.0.0.0/0 out", false, r));
    CHECK(r.direction == "out");

    CHECK(!parse_tuple("allow tcp", false, r));

    CHECK(parse_tuple("allow udp 6000:6007 0.0.0.0/0 any 0.0.0.0/0 in", false, r));
    CHECK(r.port_matches(6003) && !r.port_matches(6008));
    CHECK(parse_tuple("allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in", false, r));
    CHECK(r.port_matches(443) && !r.port_matches(8080));

    CHECK(parse_tuple("allow tcp 22 0.0.0.0/0 any 10.0.0.0/8 in comment=" + hex_encode("ipdoit:mynet:12"), false, r));
    CHECK(r.comment == "ipdoit:mynet:12" && r.mynet_id() == 12);
}

void test_dry_run_sections() {
    const std::string out =
        "*filter\n:ufw-user-input - [0:0]\n### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"
        "COMMIT\n*filter\n:ufw6-user-input - [0:0]\n### tuple ### deny tcp 22 ::/0 any ::/0 in\n";
    std::vector<Rule> v4, v6;
    parse_dry_run(out, v4, v6);
    CHECK(v4.size() == 1 && v6.size() == 1);
    CHECK(v4[0].action == "allow" && !v4[0].v6);
    CHECK(v6[0].action == "deny" && v6[0].v6);
}

void test_ss() {
    const std::string out =
        "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=500,fd=3))\n"
        "tcp LISTEN 0 128 [::]:22 [::]:* users:((\"sshd\",pid=500,fd=4))\n"
        "tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=1,fd=1))\n"
        "udp UNCONN 0 0 *:5353 *:* users:((\"avahi-daemon\",pid=7,fd=12))\n"
        "udp UNCONN 0 0 [fe80::1%wlan0]:546 [::]:*\n";
    const auto s = parse_ss(out);
    CHECK(s.size() == 5);
    CHECK(s[0].proto == "tcp" && s[0].port == 22 && s[0].address == "0.0.0.0" && s[0].process == "sshd");
    CHECK(s[1].address == "::");
    CHECK(s[2].address == "127.0.0.53" && s[2].port == 53);
    CHECK(s[3].dual_stack() && s[3].proto == "udp");
    CHECK(s[4].address == "fe80::1" && s[4].process.empty());
}

void test_networks() {
    const std::string addrs =
        "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
        "3: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic wlan0\\ x\n"
        "3: wlan0    inet6 2001:db8:5:6:aaaa::1/64 scope global dynamic mngtmpaddr\\ x\n"
        "3: wlan0    inet6 fe80::1/64 scope link\\ x\n"
        "4: usb0    inet 10.42.0.2/24 brd 10.42.0.255 scope global usb0\\ x\n";
    const std::string routes = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n";
    const std::string neigh = "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
                              "10.42.0.1 dev usb0 lladdr 11:22:33:44:55:66 STALE\n";
    const auto n = parse_networks(addrs, routes, neigh);
    CHECK(n.size() == 2);
    CHECK(n[0].iface == "wlan0" && n[0].subnet4 == "192.168.1.0/24");
    CHECK(n[0].subnet6 == "2001:db8:5:6::/64");
    CHECK(n[0].gateway == "192.168.1.1" && n[0].gw_mac == "aa:bb:cc:dd:ee:ff");
    CHECK(n[0].key() == "gw:aa:bb:cc:dd:ee:ff");
    CHECK(n[1].iface == "usb0" && n[1].gateway.empty() && n[1].key() == "if:usb0");
    CHECK(primary_network(n) == &n[0]);
}

void test_status() {
    const auto st = parse_status_verbose(
        "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n");
    CHECK(st.active && st.default_in == "deny" && st.default_out == "allow" &&
          st.default_routed == "disabled");
    CHECK(!parse_status_verbose("Status: inactive\n").active);
}

void test_config_files() {
    std::vector<Template> t(1);
    t[0].id = 3;
    t[0].action = "limit";
    t[0].proto = "tcp";
    t[0].port = "22";
    t[0].scope = "whitelisted";
    t[0].comment = "ssh from home";
    const auto back = parse_templates(format_templates(t));
    CHECK(back.size() == 1 && back[0].id == 3 && back[0].comment == "ssh from home");
    CHECK(parse_templates("9 explode tcp 22 any -\n").empty());

    std::vector<WhitelistEntry> w = {{"gw:aa:bb:cc:dd:ee:ff", "192.168.1.0/24", "Home Wi-Fi"}};
    const auto wb = parse_whitelist(format_whitelist(w));
    CHECK(wb.size() == 1 && wb[0].name == "Home Wi-Fi");
    CHECK(parse_whitelist("bogus 1.2.3.0/24 x\n").empty());

    CHECK(valid_port("22") && valid_port("6000:6007") && valid_port("80,443"));
    CHECK(!valid_port("0") && !valid_port("70000") && !valid_port("9:3") && !valid_port("80,"));
}

State sample_state(bool active) {
    State st;
    st.ok = true;
    st.status.active = active;
    st.status.default_in = "deny";
    Network n;
    n.iface = "wlan0";
    n.subnet4 = "192.168.1.0/24";
    n.gateway = "192.168.1.1";
    n.gw_mac = "aa:bb:cc:dd:ee:ff";
    st.networks = {n};
    st.sockets = parse_ss(
        "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
        "tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:((\"python3\",pid=2,fd=3))\n"
        "tcp LISTEN 0 128 0.0.0.0:9000 0.0.0.0:* users:((\"srv\",pid=3,fd=3))\n"
        "tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\",pid=4,fd=3))\n"
        "udp UNCONN 0 0 *:5353 *:* users:((\"avahi-daemon\",pid=5,fd=3))\n");
    st.rules4 = parse_rules_file(
        "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"
        "### tuple ### allow tcp 8080 0.0.0.0/0 any 192.168.1.0/24 in\n"
        "### tuple ### allow tcp 9000 0.0.0.0/0 any 10.0.0.0/8 in\n"
        "### tuple ### allow udp 5353 0.0.0.0/0 any 0.0.0.0/0 in\n", false);
    st.rules6 = parse_rules_file("", true);
    return st;
}

const PortRow* find_row(const std::vector<PortRow>& rows, int port) {
    for (const auto& r : rows) {
        if (r.port == port) return &r;
    }
    return nullptr;
}

void test_verdicts() {
    auto st = sample_state(true);
    const auto rows = port_rows(st);
    CHECK(rows.size() == 5);
    CHECK(find_row(rows, 22)->v4 == Verdict::Allowed);
    CHECK(find_row(rows, 8080)->v4 == Verdict::LanOnly);
    CHECK(find_row(rows, 9000)->v4 == Verdict::Partial);
    CHECK(find_row(rows, 631)->v4 == Verdict::LocalOnly);
    // dual-stack 5353: allowed on v4, no v6 rule -> blocked on v6
    const auto* mdns = find_row(rows, 5353);
    CHECK(mdns->v4 == Verdict::Allowed && mdns->v6 == Verdict::Blocked);
    CHECK(mdns->summary() == "v4 Allowed, v6 Blocked");

    // first match wins: a deny before the allow blocks
    std::vector<Rule> r = parse_rules_file(
        "### tuple ### deny tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"
        "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n", false);
    CHECK(evaluate(st.status, r, false, "tcp", 22, "0.0.0.0", {}) == Verdict::Blocked);
    // limit
    r = parse_rules_file("### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n", false);
    CHECK(evaluate(st.status, r, false, "tcp", 22, "0.0.0.0", {}) == Verdict::Limited);
    // interface-specific allow is partial
    r = parse_rules_file("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_wlan0\n", false);
    CHECK(evaluate(st.status, r, false, "tcp", 22, "0.0.0.0", {}) == Verdict::Partial);
    // default allow
    Status open = st.status;
    open.default_in = "allow";
    CHECK(evaluate(open, {}, false, "tcp", 4444, "0.0.0.0", {}) == Verdict::Allowed);
    // inactive
    auto off = sample_state(false);
    CHECK(find_row(port_rows(off), 9000)->v4 == Verdict::FirewallOff);
}

void test_mynet_sync() {
    std::vector<Template> t(2);
    t[0] = {1, "allow", "tcp", "8080", "whitelisted", "web"};
    t[1] = {2, "limit", "tcp", "22", "any", ""};
    Network home;
    home.iface = "wlan0";
    home.subnet4 = "192.168.1.0/24";
    home.subnet6 = "2001:db8::/64";
    home.gateway = "192.168.1.1";
    home.gw_mac = "aa:bb:cc:dd:ee:ff";
    const std::vector<WhitelistEntry> wl = {{"gw:aa:bb:cc:dd:ee:ff", "192.168.1.0/24", "Home"}};

    // whitelisted, nothing live yet: 2 templates x (v4 + v6) = 4 adds
    auto plan = plan_mynet_sync(t, {home}, wl, {}, {});
    CHECK(plan.remove.empty() && plan.add.size() == 4);

    // not whitelisted: only the "any" template
    plan = plan_mynet_sync(t, {home}, {}, {}, {});
    CHECK(plan.add.size() == 2);

    // moved to a cafe: old live rules removed, "any" template re-added for new subnet
    const auto live4 = parse_rules_file(
        "### tuple ### allow tcp 8080 0.0.0.0/0 any 192.168.1.0/24 in comment=" +
            hex_encode("ipdoit:mynet:1 web") + "\n"
        "### tuple ### limit tcp 22 0.0.0.0/0 any 192.168.1.0/24 in comment=" +
            hex_encode("ipdoit:mynet:2") + "\n"
        "### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in\n", false);
    Network cafe;
    cafe.iface = "wlan0";
    cafe.subnet4 = "10.9.0.0/16";
    cafe.gateway = "10.9.0.1";
    cafe.gw_mac = "12:34:56:78:9a:bc";
    plan = plan_mynet_sync(t, {cafe}, wl, live4, {});
    CHECK(plan.remove.size() == 2);
    CHECK(plan.add.size() == 1);
    CHECK(join_args(plan.add[0]) ==
          "limit proto tcp from 10.9.0.0/16 to any port 22 comment ipdoit:mynet:2");
    CHECK(join_args(plan.remove[0]) == "delete allow proto tcp from 192.168.1.0/24 to any port 8080");

    // just reconnected at home, gateway MAC not resolved yet: keep the live rules, add none
    Network unresolved = home;
    unresolved.gw_mac.clear();
    unresolved.subnet6.clear();
    plan = plan_mynet_sync(t, {unresolved}, wl, live4, {});
    CHECK(plan.remove.empty());
    CHECK(plan.add.empty());

    // back home with rules already live: nothing to do for v4
    plan = plan_mynet_sync(t, {home}, wl, live4, {});
    CHECK(plan.remove.empty() && plan.add.size() == 2); // the two v6 rules
}

void test_freeform_and_form() {
    std::vector<std::string> args;
    CHECK(validate_freeform("allow from 192.168.1.0/24 to any port 22 proto tcp", args).empty());
    CHECK(args.size() == 9 && args[0] == "allow");
    CHECK(validate_freeform("ufw insert 1 deny 25 comment 'no smtp here'", args).empty());
    CHECK(args[0] == "insert" && args.back() == "no smtp here");
    CHECK(!validate_freeform("reset", args).empty());
    CHECK(!validate_freeform("disable", args).empty());
    CHECK(!validate_freeform("delete 1", args).empty());
    CHECK(!validate_freeform("allow 22; rm -rf /", args).empty() || args[1] == "22;");
    CHECK(!validate_freeform("allow --force 22", args).empty());
    CHECK(!validate_freeform("insert x allow 22", args).empty());
    CHECK(!validate_freeform("allow 'unterminated", args).empty());

    RuleForm f;
    f.port = "22";
    CHECK(validate_form(f).empty());
    CHECK(join_args(form_args(f)) == "allow proto tcp from any to any port 22");
    f.source = RuleForm::Source::Custom;
    f.custom_source = "10.0.0.0/8";
    f.comment = "lab";
    CHECK(join_args(form_args(f)) == "allow proto tcp from 10.0.0.0/8 to any port 22 comment lab");
    f.custom_source = "nope";
    CHECK(!validate_form(f).empty());
    f.source = RuleForm::Source::MyNetWhitelisted;
    f.direction = "out";
    CHECK(!validate_form(f).empty());
    f.direction = "in";
    CHECK(validate_form(f).empty());
    CHECK(form_template(f).scope == "whitelisted");
    f.port = "6000:6007";
    f.proto = "any";
    CHECK(!validate_form(f).empty());
}

void test_ssh_guard() {
    auto st = sample_state(true);
    // deleting the SSH allow while incoming is denied -> warning
    std::vector<Rule> after(st.rules4.begin() + 1, st.rules4.end());
    CHECK(!ssh_guard(st, st.status, after, st.rules6).empty());
    // unchanged -> no warning
    CHECK(ssh_guard(st, st.status, st.rules4, st.rules6).empty());
    // enabling with no SSH rule while off -> warning
    auto off = sample_state(false);
    Status on = off.status;
    on.active = true;
    CHECK(!ssh_guard(off, on, after, off.rules6).empty());
    // no sshd -> never warns
    st.sockets = parse_ss("tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=3))\n");
    CHECK(ssh_guard(st, st.status, {}, {}).empty());
}

} // namespace

int main() {
    test_cidr();
    test_tuples();
    test_dry_run_sections();
    test_ss();
    test_networks();
    test_status();
    test_config_files();
    test_verdicts();
    test_mynet_sync();
    test_freeform_and_form();
    test_ssh_guard();
    if (failures) {
        std::fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    std::printf("all fw tests passed\n");
    return 0;
}
