/*
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "net.h"

#include <string>
#include <vector>

namespace fw {

// One ufw user rule, as stored in a "### tuple ###" line of user.rules / user6.rules.
struct Rule {
    std::string action;     // allow / deny / reject / limit (log suffix stripped)
    bool log = false;       // action had _log / _log-all
    bool forward = false;   // "route:" rule
    std::string proto;      // tcp / udp / any / ...
    std::string dport;      // "22", "6000:6007", "80,443", "any"
    std::string dst;        // CIDR
    std::string sport;
    std::string src;        // CIDR
    std::string dapp, sapp; // app profile names, empty if none
    std::string direction;  // in / out
    std::string iface_in, iface_out;
    std::string comment;    // decoded
    bool v6 = false;
    std::string raw;        // tuple text after "### tuple ###", comment included

    bool is_mynet() const;  // comment tagged "ipdoit:mynet:<id>"
    int mynet_id() const;   // -1 when not tagged
    bool port_matches(int port) const;
};

struct Socket {
    std::string proto;   // tcp / udp
    std::string address; // as printed, without brackets or zone: "0.0.0.0", "::", "*", "127.0.0.1"
    int port = 0;
    std::string process; // first process name, may be empty
    bool dual_stack() const { return address == "*"; }
};

struct Network {
    std::string iface;
    std::string subnet4;  // "192.168.1.0/24", may be empty
    std::string subnet6;  // global prefix, may be empty
    std::string gateway;  // IPv4 default gateway on this iface, may be empty
    std::string gw_mac;   // gateway MAC, may be empty
    // Whitelist identity: "gw:<mac>" or "if:<iface>"
    std::string key() const { return gw_mac.empty() ? "if:" + iface : "gw:" + gw_mac; }
};

struct WhitelistEntry {
    std::string key;     // "gw:<mac>" or "if:<iface>"
    std::string subnet4;
    std::string name;
};

struct Template {
    int id = 0;
    std::string action;  // allow / limit / deny / reject
    std::string proto;   // tcp / udp / any
    std::string port;    // "22", "6000:6007"
    std::string scope;   // "whitelisted" or "any"
    std::string comment;
};

struct Status {
    bool active = false;
    std::string default_in = "deny";
    std::string default_out = "allow";
    std::string default_routed = "disabled";
};

// Everything the app shows, read in one privileged helper call.
struct State {
    bool ok = false;
    std::string error;
    Status status;
    std::vector<Rule> rules4;
    std::vector<Rule> rules6;
    std::vector<Socket> sockets;
    std::vector<Network> networks;
    std::vector<WhitelistEntry> whitelist;
    std::vector<Template> templates;
    int backups = 0;
};

} // namespace fw
