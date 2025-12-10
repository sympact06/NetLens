// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include "ScanSettings.h"
#include "ScanResult.h"
#include <functional>

namespace netlens {

/// <summary>
/// Progress information for an ongoing scan.
/// </summary>
struct ScanProgress {
    size_t total_hosts;
    size_t completed_hosts;
    std::string current_ip;
    size_t total_ports;
    size_t completed_ports;

    ScanProgress()
        : total_hosts(0)
        , completed_hosts(0)
        , current_ip()
        , total_ports(0)
        , completed_ports(0) {}
};

/// <summary>
/// Callback function type for scan progress updates.
/// </summary>
using ProgressCallback = std::function<void(const ScanProgress&)>;

/// <summary>
/// Main scanner class responsible for executing network scans.
/// </summary>
class Scanner {
public:
    /// <summary>
    /// Constructs a new Scanner instance.
    /// </summary>
    Scanner();

    /// <summary>
    /// Destroys the Scanner instance.
    /// </summary>
    ~Scanner();

    /// <summary>
    /// Performs a network scan based on the provided settings.
    /// </summary>
    /// <param name="settings">Scan configuration settings.</param>
    /// <returns>Scan results.</returns>
    ScanResult scan(const ScanSettings& settings);

    /// <summary>
    /// Performs a network scan with progress reporting.
    /// </summary>
    /// <param name="settings">Scan configuration settings.</param>
    /// <param name="progressCallback">Callback for progress updates.</param>
    /// <returns>Scan results.</returns>
    ScanResult scan(const ScanSettings& settings, ProgressCallback progressCallback);
};

} // namespace netlens
