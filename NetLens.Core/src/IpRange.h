// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <string>
#include <vector>
#include <stdexcept>

namespace netlens::internal {

/// <summary>
/// Exception thrown when IP range operations fail.
/// </summary>
class IpRangeException : public std::runtime_error {
public:
    explicit IpRangeException(const std::string& message)
        : std::runtime_error(message) {}
};

/// <summary>
/// Utility for handling IPv4 address ranges.
/// </summary>
class IpRange {
public:
    /// <summary>
    /// Parses an IPv4 address string into a 32-bit integer.
    /// </summary>
    /// <param name="ip">IPv4 address in dotted notation (e.g., "192.168.1.1")</param>
    /// <returns>32-bit integer representation</returns>
    /// <exception cref="IpRangeException">Thrown if the IP address is invalid</exception>
    static uint32_t parse(const std::string& ip);

    /// <summary>
    /// Converts a 32-bit integer to an IPv4 address string.
    /// </summary>
    /// <param name="ip">32-bit integer representation</param>
    /// <returns>IPv4 address in dotted notation</returns>
    static std::string toString(uint32_t ip);

    /// <summary>
    /// Generates all IPv4 addresses in a range from start to end (inclusive).
    /// </summary>
    /// <param name="start_ip">Starting IPv4 address string</param>
    /// <param name="end_ip">Ending IPv4 address string</param>
    /// <returns>Vector of IPv4 address strings</returns>
    /// <exception cref="IpRangeException">Thrown if the range is invalid</exception>
    static std::vector<std::string> enumerate(const std::string& start_ip, const std::string& end_ip);

    /// <summary>
    /// Validates that a string is a valid IPv4 address.
    /// </summary>
    /// <param name="ip">String to validate</param>
    /// <returns>True if valid, false otherwise</returns>
    static bool isValid(const std::string& ip);
};

} // namespace netlens::internal
