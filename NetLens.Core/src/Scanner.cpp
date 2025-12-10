// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "netlens/Scanner.h"
#include "AsyncScanEngine.h"
#include "IpRange.h"
#include <stdexcept>

namespace netlens {

Scanner::Scanner() {
    // Constructor
}

Scanner::~Scanner() {
    // Destructor
}

ScanResult Scanner::scan(const ScanSettings& settings) {
    // Call overload with null progress callback
    return scan(settings, nullptr);
}

ScanResult Scanner::scan(const ScanSettings& settings, ProgressCallback progressCallback) {
    // Validate settings
    if (settings.start_ip.empty() || settings.end_ip.empty()) {
        throw std::invalid_argument("Start IP and End IP must be provided");
    }

    if (settings.ports.empty()) {
        throw std::invalid_argument("At least one port must be specified");
    }

    if (!internal::IpRange::isValid(settings.start_ip)) {
        throw std::invalid_argument("Invalid start IP address: " + settings.start_ip);
    }

    if (!internal::IpRange::isValid(settings.end_ip)) {
        throw std::invalid_argument("Invalid end IP address: " + settings.end_ip);
    }

    // Create async scan engine and execute scan
    internal::AsyncScanEngine engine;
    return engine.executeScan(settings, progressCallback);
}

} // namespace netlens
