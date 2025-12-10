// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <string>
#include <vector>
#include "PortResult.h"

namespace netlens {

/// <summary>
/// Represents the scan results for a single host.
/// </summary>
struct HostResult {
    /// <summary>
    /// IP address or hostname of the scanned host.
    /// </summary>
    std::string address;

    /// <summary>
    /// True if the host appears to be alive/reachable.
    /// </summary>
    bool is_alive;

    /// <summary>
    /// Collection of port scan results for this host.
    /// </summary>
    std::vector<PortResult> ports;

    HostResult() : address(), is_alive(false), ports() {}

    HostResult(const std::string& addr, bool alive)
        : address(addr), is_alive(alive), ports() {}
};

} // namespace netlens
