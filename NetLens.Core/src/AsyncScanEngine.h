// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <netlens/Scanner.h>
#include <memory>
#include <vector>
#include <string>

// Forward declarations to avoid exposing Asio in header
namespace asio {
    class io_context;
    class thread_pool;
}

namespace netlens::internal {

/// <summary>
/// Internal asynchronous scanning engine using Asio.
/// Manages concurrent TCP port scanning across multiple hosts and ports.
/// </summary>
class AsyncScanEngine {
public:
    /// <summary>
    /// Constructs the async scan engine.
    /// </summary>
    AsyncScanEngine();

    /// <summary>
    /// Destroys the engine and cleans up resources.
    /// </summary>
    ~AsyncScanEngine();

    // Non-copyable, non-movable
    AsyncScanEngine(const AsyncScanEngine&) = delete;
    AsyncScanEngine& operator=(const AsyncScanEngine&) = delete;
    AsyncScanEngine(AsyncScanEngine&&) = delete;
    AsyncScanEngine& operator=(AsyncScanEngine&&) = delete;

    /// <summary>
    /// Executes a scan based on settings.
    /// Blocks until scan is complete.
    /// </summary>
    /// <param name="settings">Scan configuration</param>
    /// <param name="progressCallback">Optional progress callback</param>
    /// <returns>Complete scan results</returns>
    ScanResult executeScan(const ScanSettings& settings, netlens::ProgressCallback progressCallback);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void scanHost(const std::string& ip, const std::vector<uint16_t>& ports,
                  uint32_t timeout_ms, HostResult& result);
};

} // namespace netlens::internal
