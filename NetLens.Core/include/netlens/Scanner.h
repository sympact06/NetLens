// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include "ScanSettings.h"
#include "ScanResult.h"

namespace netlens {

/// <summary>
/// Main scanner class responsible for executing network scans.
/// Phase 0: Returns placeholder/dummy data only.
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
    /// Phase 0: Returns hard-coded placeholder data.
    /// </summary>
    /// <param name="settings">Scan configuration settings.</param>
    /// <returns>Scan results containing placeholder data.</returns>
    ScanResult scan(const ScanSettings& settings);
};

} // namespace netlens
