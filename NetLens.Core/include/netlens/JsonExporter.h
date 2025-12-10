// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <netlens/ScanResult.h>
#include <string>

namespace netlens {

/// <summary>
/// Utilities for exporting scan results to JSON format.
/// </summary>
class JsonExporter {
public:
    /// <summary>
    /// Converts a ScanResult to JSON string.
    /// </summary>
    /// <param name="result">The scan result to export</param>
    /// <param name="pretty">If true, formats JSON with indentation</param>
    /// <returns>JSON string representation</returns>
    static std::string toJson(const ScanResult& result, bool pretty = true);

    /// <summary>
    /// Saves a ScanResult to a JSON file.
    /// </summary>
    /// <param name="result">The scan result to export</param>
    /// <param name="filepath">Path to the output JSON file</param>
    /// <param name="pretty">If true, formats JSON with indentation</param>
    /// <returns>True if successful, false otherwise</returns>
    static bool saveToFile(const ScanResult& result, const std::string& filepath, bool pretty = true);
};

} // namespace netlens
