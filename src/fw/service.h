/*
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "model.h"
#include "privilege.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace fw {

// Runs ipdoit-helper commands on a worker thread, one at a time. The UI polls snapshot().
class FirewallService {
public:
    enum class Op { None, Refresh, DryRun, Apply };

    struct Result {
        Op op = Op::None;
        bool ok = false;
        std::string output; // combined stdout/stderr
        uint32_t id = 0;    // request id from submit()
    };

    struct Snapshot {
        bool busy = false;
        uint32_t revision = 0;
        State state;        // last successful refresh
        Result last;        // last finished request
    };

    explicit FirewallService(Privilege& privilege);
    ~FirewallService();

    FirewallService(const FirewallService&) = delete;
    FirewallService& operator=(const FirewallService&) = delete;

    // Each returns a request id, or 0 when busy.
    uint32_t refresh();
    uint32_t dry_run(const std::vector<std::string>& ufw_args);
    // `helper_args` is a helper command line, e.g. {"add", "allow", "22"}. Refreshes after.
    uint32_t apply(const std::vector<std::string>& helper_args);

    Snapshot snapshot() const;
    bool busy() const;

    static std::string helper_path();

private:
    uint32_t submit(Op op, std::vector<std::string> helper_args, bool refresh_after);
    int run_helper(const std::vector<std::string>& args, std::string& output);
    void join();

    Privilege& privilege_;
    std::thread worker_;
    std::atomic<bool> busy_{false};
    uint32_t next_id_ = 1;

    mutable std::mutex mutex_;
    Snapshot snap_;
};

} // namespace fw
