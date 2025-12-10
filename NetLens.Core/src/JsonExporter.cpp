// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "netlens/JsonExporter.h"
#include <json.hpp>
#include <fstream>

using json = nlohmann::json;

namespace netlens {

std::string JsonExporter::toJson(const ScanResult& result, bool pretty) {
    json j;

    // Export settings
    j["settings"] = {
        {"startIp", result.settings.start_ip},
        {"endIp", result.settings.end_ip},
        {"ports", result.settings.ports},
        {"timeoutMs", result.settings.timeout_ms},
        {"maxConcurrency", result.settings.max_concurrency}
    };

    // Export hosts
    j["hosts"] = json::array();
    for (const auto& host : result.hosts) {
        json host_obj = {
            {"ip", host.address},
            {"isAlive", host.is_alive},
            {"ports", json::array()}
        };

        for (const auto& port : host.ports) {
            json port_obj = {
                {"port", port.port},
                {"isOpen", port.is_open}
            };

            if (!port.banner.empty()) {
                port_obj["banner"] = port.banner;
            }

            host_obj["ports"].push_back(port_obj);
        }

        j["hosts"].push_back(host_obj);
    }

    // Export metadata
    j["metadata"] = {
        {"version", "1.0"},
        {"tool", "NetLens"},
        {"totalHosts", result.hosts.size()},
        {"aliveHosts", std::count_if(result.hosts.begin(), result.hosts.end(), 
                                       [](const HostResult& h) { return h.is_alive; })}
    };

    return pretty ? j.dump(2) : j.dump();
}

bool JsonExporter::saveToFile(const ScanResult& result, const std::string& filepath, bool pretty) {
    try {
        std::string json_str = toJson(result, pretty);
        std::ofstream file(filepath);
        
        if (!file.is_open()) {
            return false;
        }

        file << json_str;
        file.close();
        return true;
    }
    catch (...) {
        return false;
    }
}

} // namespace netlens
