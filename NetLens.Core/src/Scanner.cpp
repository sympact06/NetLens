// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "netlens/Scanner.h"

namespace netlens {

Scanner::Scanner() {
    // Phase 0: No initialization needed
}

Scanner::~Scanner() {
    // Phase 0: No cleanup needed
}

ScanResult Scanner::scan(const ScanSettings& settings) {
    // Phase 0: Return hard-coded placeholder data
    ScanResult result(settings);

    // Create a dummy host result
    HostResult host1("192.168.1.100", true);
    host1.ports.push_back(PortResult(80, true, "HTTP"));
    host1.ports.push_back(PortResult(443, true, "HTTPS"));
    host1.ports.push_back(PortResult(22, false));

    HostResult host2("192.168.1.101", true);
    host2.ports.push_back(PortResult(3389, true, "RDP"));
    host2.ports.push_back(PortResult(445, true, "SMB"));

    result.hosts.push_back(host1);
    result.hosts.push_back(host2);

    return result;
}

} // namespace netlens
