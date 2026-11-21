/*
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "model.h"

#include <string>
#include <vector>

namespace fw {

// ---------------------------------------------------------------- port verdicts

enum class Verdict {
    NotApplicable, // e.g. no IPv6 socket for this port
    FirewallOff,
    LocalOnly,
    Allowed,
    Limited,
    LanOnly,       // allowed only from the current network(s)
    Partial,       // allowed only from some sources / interfaces
    Blocked,
};

const char* verdict_label(Verdict v);
bool verdict_reachable(Verdict v); // anything but Blocked / NotApplicable

// Whether UFW lets traffic for (family, proto, port) to `address` in from outside.
// `local_subnets` are the current network(s), used to tell LanOnly from Partial.
Verdict evaluate(const Status& status, const std::vector<Rule>& rules, bool v6,
                 const std::string& proto, int port, const std::string& address,
                 const std::vector<std::string>& local_subnets);

// One row on the Ports page: a listening port with its IPv4 and IPv6 verdicts.
struct PortRow {
    std::string proto;
    int port = 0;
    std::string process;
    std::string bind; // short description: "all", "127.0.0.1", ...
    Verdict v4 = Verdict::NotApplicable;
    Verdict v6 = Verdict::NotApplicable;
    std::string summary() const; // "Allowed", or "v4 Allowed, v6 Blocked"
};

std::vector<PortRow> port_rows(const State& state);
std::vector<PortRow> port_rows(const State& state, const Status& status,
                               const std::vector<Rule>& rules4,
                               const std::vector<Rule>& rules6);

// ---------------------------------------------------------------- port toggles

// The Ports page's per-port switch. Blocked: no rule opens it. Lan: a My network
// (whitelisted only) rule. Allowed: an allow/limit rule from anywhere.
enum class PortState { Blocked, Lan, Allowed };
const char* port_state_label(PortState s);
PortState next_port_state(PortState s); // Blocked -> Lan -> Allowed -> Blocked

// One row of the merged list: listening ports plus ports that only have rules.
struct PortEntry {
    std::string proto;   // tcp / udp (any for rules without a protocol)
    int port = 0;
    std::string process; // empty when nothing listens
    bool listening = false;
    bool local_only = false; // listens on loopback only
    PortState state = PortState::Blocked;
    PortRow verdict;         // effective verdict from all rules (listening ports)
    bool overridden = false; // another rule makes the verdict differ from the switch
};

PortState port_state(const State& state, const std::string& proto, int port);
std::vector<PortEntry> port_entries(const State& state);
bool is_ssh_port(const State& state, const std::string& proto, int port);
// Rules as they would be after `port-set` (for the SSH guard).
void simulate_port_set(const State& state, const std::string& proto, int port,
                       PortState target, std::vector<Rule>& after4,
                       std::vector<Rule>& after6);

// ---------------------------------------------------------------- networks

bool is_whitelisted(const Network& net, const std::vector<WhitelistEntry>& whitelist);
// The network with the default route, or the first one. nullptr when offline.
const Network* primary_network(const std::vector<Network>& nets);
std::vector<std::string> local_subnets(const std::vector<Network>& nets);

// ---------------------------------------------------------------- My network sync

// ufw arguments (after "ufw") for one live rule made from a template.
std::vector<std::string> mynet_rule_args(const Template& t, const std::string& subnet);
std::vector<std::string> mynet_delete_args(const Rule& live);

struct SyncPlan {
    std::vector<std::vector<std::string>> remove; // ufw args, "delete ..." included
    std::vector<std::vector<std::string>> add;
};

SyncPlan plan_mynet_sync(const std::vector<Template>& templates,
                         const std::vector<Network>& networks,
                         const std::vector<WhitelistEntry>& whitelist,
                         const std::vector<Rule>& rules4, const std::vector<Rule>& rules6);

// ---------------------------------------------------------------- user rules

// Split free-form text into ufw arguments and check it is a rule command
// (allow/deny/reject/limit, optionally after "insert N"). Returns an error or "".
std::string validate_freeform(const std::string& text, std::vector<std::string>& args);
// Same check on already-split arguments (used by the helper).
std::string validate_rule_args(const std::vector<std::string>& args);

struct RuleForm {
    std::string action = "allow";   // allow deny reject limit
    std::string direction = "in";   // in out
    std::string port;               // required
    std::string proto = "tcp";      // tcp udp any
    enum class Source { Any, MyNetWhitelisted, MyNetAny, Custom } source = Source::Any;
    std::string custom_source;      // IP or CIDR when source == Custom
    std::string comment;

    bool is_mynet() const { return source == Source::MyNetWhitelisted || source == Source::MyNetAny; }
};

// Error text, or "" if the form can be applied.
std::string validate_form(const RuleForm& form);
// ufw arguments for a non-My-network form.
std::vector<std::string> form_args(const RuleForm& form);
// Template for a My network form (id filled in by the helper).
Template form_template(const RuleForm& form);

struct Preset {
    const char* label;
    const char* action;
    const char* port;
    const char* proto;
};
const std::vector<Preset>& presets();

std::string join_args(const std::vector<std::string>& args); // for display, quotes spaces

// Short one-line description of a rule for the Rules page.
std::string describe_rule(const Rule& r);
std::string describe_template(const Template& t);
// Same, with the "My network" source names supplied (the app passes translated ones).
std::string describe_template(const Template& t, const std::string& my_network,
                              const std::string& my_network_whitelisted);

// ---------------------------------------------------------------- SSH guard

// Non-loopback sockets owned by sshd.
std::vector<Socket> ssh_sockets(const std::vector<Socket>& sockets);
// Warning text when `after` would block SSH that `before` lets in; "" when fine or no sshd.
std::string ssh_guard(const State& state, const Status& after_status,
                      const std::vector<Rule>& after4, const std::vector<Rule>& after6);
// The sshd ports ssh_guard() would warn about, as "22" or "22, 2222"; "" when fine.
std::string ssh_blocked_ports(const State& state, const Status& after_status,
                              const std::vector<Rule>& after4, const std::vector<Rule>& after6);

} // namespace fw
