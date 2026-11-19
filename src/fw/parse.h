/*
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "model.h"

#include <string>
#include <vector>

namespace fw {

std::string hex_encode(const std::string& s);
std::string hex_decode(const std::string& hex);

// One tuple line (with or without the "### tuple ###" prefix). Returns false if malformed.
bool parse_tuple(const std::string& line, bool v6, Rule& out);
// All tuples in a user.rules / user6.rules file.
std::vector<Rule> parse_rules_file(const std::string& text, bool v6);
// Tuples in `ufw --dry-run` output, split by section (":ufw6-" chains are IPv6).
void parse_dry_run(const std::string& text, std::vector<Rule>& v4, std::vector<Rule>& v6);

// `ss -H -tulpn`
std::vector<Socket> parse_ss(const std::string& text);

// `ip -o addr show up`, `ip route show default`, `ip neigh show`
std::vector<Network> parse_networks(const std::string& addrs, const std::string& routes,
                                    const std::string& neigh);

// `ufw status verbose` (LC_ALL=C)
Status parse_status_verbose(const std::string& text);

// /etc/ipdoit/whitelist.conf: "<key> <subnet4> <name...>"
std::vector<WhitelistEntry> parse_whitelist(const std::string& text);
std::string format_whitelist(const std::vector<WhitelistEntry>& entries);

// /etc/ipdoit/mynet-rules.conf: "<id> <action> <proto> <port> <scope> <comment-hex|->"
std::vector<Template> parse_templates(const std::string& text);
std::string format_templates(const std::vector<Template>& templates);

// Field checks shared by the form, the helper and the templates file.
bool valid_action(const std::string& s);   // allow deny reject limit
bool valid_proto(const std::string& s);    // tcp udp any
bool valid_port(const std::string& s);     // 1-65535, a:b range, or comma list
bool valid_scope(const std::string& s);    // whitelisted any

// The helper's `state` output: "@section" headers followed by raw lines.
State parse_state(const std::string& text);

} // namespace fw
