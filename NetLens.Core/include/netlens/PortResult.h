// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <cstdint>
#include <string>

namespace netlens {

/// <summary>
/// Represents the result of scanning a single port on a host.
/// </summary>
struct PortResult {
    /// <summary>
    /// The port number that was scanned.
    /// </summary>
    uint16_t port;

    /// <summary>
    /// True if the port is open, false otherwise.
    /// </summary>
    bool is_open;

    /// <summary>
    /// Optional service banner or identification string.
    /// Empty in Phase 0 (placeholder only).
    /// </summary>
    std::string banner;

    PortResult() : port(0), is_open(false), banner() {}

    PortResult(uint16_t p, bool open, const std::string& b = "")
        : port(p), is_open(open), banner(b) {}
};

} // namespace netlens
