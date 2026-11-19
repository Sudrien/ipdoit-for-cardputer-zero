/*
 * SPDX-License-Identifier: MIT
 */

#include "service.h"

#include "parse.h"
#include "process.h"

#include <cstdlib>

namespace fw {
namespace {

void wipe(std::string& s) {
    volatile char* p = s.empty() ? nullptr : &s[0];
    for (size_t i = 0; i < s.size(); ++i) {
        p[i] = 0;
    }
    s.clear();
}

} // namespace

FirewallService::FirewallService(Privilege& privilege) : privilege_(privilege) {}

FirewallService::~FirewallService() {
    join();
}

void FirewallService::join() {
    if (worker_.joinable()) {
        worker_.join();
    }
}

std::string FirewallService::helper_path() {
    // Override for development builds; sudo needs an absolute path.
    if (const char* p = std::getenv("IPDOIT_HELPER"); p && p[0] == '/') {
        return p;
    }
    return "/usr/libexec/ipdoit/ipdoit-helper";
}

int FirewallService::run_helper(const std::vector<std::string>& args, std::string& output) {
    std::vector<std::string> argv = {helper_path()};
    argv.insert(argv.end(), args.begin(), args.end());
    RunOptions run;
    run.argv = privilege_.wrap(argv, run.stdin_data);
    run.on_line = [&output](const std::string& line) {
        output += line;
        output += '\n';
    };
    const int code = run_process(run);
    wipe(run.stdin_data);
    return code;
}

uint32_t FirewallService::refresh() {
    return submit(Op::Refresh, {"state"}, false);
}

uint32_t FirewallService::dry_run(const std::vector<std::string>& ufw_args) {
    std::vector<std::string> args = {"dry-run"};
    args.insert(args.end(), ufw_args.begin(), ufw_args.end());
    return submit(Op::DryRun, args, false);
}

uint32_t FirewallService::apply(const std::vector<std::string>& helper_args) {
    return submit(Op::Apply, helper_args, true);
}

bool FirewallService::busy() const {
    return busy_.load();
}

FirewallService::Snapshot FirewallService::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Snapshot s = snap_;
    s.busy = busy_.load();
    return s;
}

uint32_t FirewallService::submit(Op op, std::vector<std::string> helper_args,
                                 bool refresh_after) {
    if (busy_.exchange(true)) {
        return 0;
    }
    join();
    const uint32_t id = next_id_++;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++snap_.revision;
    }
    worker_ = std::thread([this, op, id, helper_args, refresh_after]() {
        Result result;
        result.op = op;
        result.id = id;
        const int code = run_helper(helper_args, result.output);
        result.ok = code == 0;

        State state;
        bool have_state = false;
        if (op == Op::Refresh) {
            state = parse_state(result.output);
            have_state = state.ok;
            if (!state.ok) {
                result.ok = false;
                result.output = state.error;
            }
        }
        else if (refresh_after) {
            std::string out;
            run_helper({"state"}, out);
            state = parse_state(out);
            have_state = state.ok;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (have_state) {
            snap_.state = std::move(state);
        }
        snap_.last = std::move(result);
        ++snap_.revision;
        busy_ = false;
    });
    return id;
}

} // namespace fw
