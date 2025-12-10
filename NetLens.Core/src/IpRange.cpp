// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "IpRange.h"
#include <sstream>
#include <regex>

namespace netlens::internal {

uint32_t IpRange::parse(const std::string& ip) {
    if (!isValid(ip)) {
        throw IpRangeException("Invalid IPv4 address: " + ip);
    }

    uint32_t result = 0;
    std::istringstream iss(ip);
    std::string octet;
    int shift = 24;

    while (std::getline(iss, octet, '.')) {
        int value = std::stoi(octet);
        result |= (static_cast<uint32_t>(value) << shift);
        shift -= 8;
    }

    return result;
}

std::string IpRange::toString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << '.'
        << ((ip >> 16) & 0xFF) << '.'
        << ((ip >> 8) & 0xFF) << '.'
        << (ip & 0xFF);
    return oss.str();
}

std::vector<std::string> IpRange::enumerate(const std::string& start_ip, const std::string& end_ip) {
    uint32_t start = parse(start_ip);
    uint32_t end = parse(end_ip);

    if (start > end) {
        throw IpRangeException("Start IP must be less than or equal to end IP");
    }

    // Prevent enormous ranges that could cause memory issues
    const uint32_t max_range = 65536; // 256 * 256
    if (end - start + 1 > max_range) {
        throw IpRangeException("IP range too large (maximum " + std::to_string(max_range) + " addresses)");
    }

    std::vector<std::string> addresses;
    addresses.reserve(static_cast<size_t>(end - start + 1));

    for (uint32_t ip = start; ip <= end; ++ip) {
        addresses.push_back(toString(ip));
    }

    return addresses;
}

bool IpRange::isValid(const std::string& ip) {
    // Simple regex for IPv4 validation
    static const std::regex ipv4_pattern(
        R"(^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    );

    return std::regex_match(ip, ipv4_pattern);
}

} // namespace netlens::internal
