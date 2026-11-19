/*
 * SPDX-License-Identifier: MIT
 */

#include "net.h"

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>

namespace fw {

Cidr Cidr::parse(const std::string& text) {
    Cidr c;
    std::string addr = text;
    int prefix = -1;
    const auto slash = text.find('/');
    if (slash != std::string::npos) {
        addr = text.substr(0, slash);
        const auto p = text.substr(slash + 1);
        if (p.empty() || p.find_first_not_of("0123456789") != std::string::npos) {
            return c;
        }
        prefix = std::atoi(p.c_str());
    }
    // strip a zone ("fe80::1%eth0")
    const auto pct = addr.find('%');
    if (pct != std::string::npos) {
        addr = addr.substr(0, pct);
    }
    if (inet_pton(AF_INET, addr.c_str(), c.bytes.data()) == 1) {
        c.v6 = false;
    }
    else if (inet_pton(AF_INET6, addr.c_str(), c.bytes.data()) == 1) {
        c.v6 = true;
    }
    else {
        return c;
    }
    c.prefix = prefix < 0 ? c.max_prefix() : prefix;
    if (c.prefix > c.max_prefix()) {
        return Cidr{};
    }
    c.valid = true;
    return c;
}

bool Cidr::contains(const Cidr& other) const {
    if (!valid || !other.valid || v6 != other.v6 || other.prefix < prefix) {
        return false;
    }
    int bits = prefix;
    for (int i = 0; bits > 0; ++i, bits -= 8) {
        const uint8_t mask = bits >= 8 ? 0xff : static_cast<uint8_t>(0xff << (8 - bits));
        if ((bytes[i] & mask) != (other.bytes[i] & mask)) {
            return false;
        }
    }
    return true;
}

Cidr Cidr::network() const {
    Cidr n = *this;
    const int len = v6 ? 16 : 4;
    for (int i = 0; i < len; ++i) {
        const int bit_start = i * 8;
        if (bit_start >= prefix) {
            n.bytes[i] = 0;
        }
        else if (prefix - bit_start < 8) {
            n.bytes[i] &= static_cast<uint8_t>(0xff << (8 - (prefix - bit_start)));
        }
    }
    return n;
}

bool Cidr::is_loopback() const {
    if (!valid) {
        return false;
    }
    if (!v6) {
        return bytes[0] == 127;
    }
    for (int i = 0; i < 15; ++i) {
        if (bytes[i]) {
            return false;
        }
    }
    return bytes[15] == 1;
}

bool Cidr::is_link_local() const {
    if (!valid) {
        return false;
    }
    if (!v6) {
        return bytes[0] == 169 && bytes[1] == 254;
    }
    return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
}

std::string Cidr::str() const {
    if (!valid) {
        return "";
    }
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(v6 ? AF_INET6 : AF_INET, bytes.data(), buf, sizeof(buf));
    std::string s = buf;
    if (prefix != max_prefix()) {
        s += "/" + std::to_string(prefix);
    }
    return s;
}

} // namespace fw
