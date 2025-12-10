// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <vector>
#include "ScanSettings.h"
#include "HostResult.h"

namespace netlens {

/// <summary>
/// Complete result of a network scan operation.
/// </summary>
struct ScanResult {
    /// <summary>
    /// The settings that were used for this scan.
    /// </summary>
    ScanSettings settings;

    /// <summary>
    /// Collection of host results from the scan.
    /// </summary>
    std::vector<HostResult> hosts;

    ScanResult() : settings(), hosts() {}

    explicit ScanResult(const ScanSettings& s)
        : settings(s), hosts() {}
};

} // namespace netlens
