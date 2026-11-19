/*
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace fw {

// An IPv4 or IPv6 address, or a CIDR block when prefix < full length.
struct Cidr {
    bool valid = false;
    bool v6 = false;
    std::array<uint8_t, 16> bytes{}; // IPv4 uses the first 4
    int prefix = 0;                  // 0..32 or 0..128

    static Cidr parse(const std::string& text); // "10.0.0.0/8", "::1", "0.0.0.0/0"
    int max_prefix() const { return v6 ? 128 : 32; }
    bool is_any() const { return valid && prefix == 0; }
    bool contains(const Cidr& other) const;   // other is inside this block
    Cidr network() const;                     // host bits cleared
    bool is_loopback() const;
    bool is_link_local() const;
    std::string str() const;                  // canonical, prefix omitted when full
};

} // namespace fw
