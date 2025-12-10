// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <netlens/Scanner.h>
#include <netlens/ScanResult.h>

namespace NetLens::ViewModels
{
    /// <summary>
    /// View model for the main window, managing scan operations and results.
    /// </summary>
    class MainViewModel
    {
    public:
        MainViewModel();
        ~MainViewModel();

        /// <summary>
        /// Executes a scan asynchronously with user-provided configuration.
        /// </summary>
        /// <param name="startIp">Starting IP address</param>
        /// <param name="endIp">Ending IP address</param>
        /// <param name="ports">Vector of ports to scan</param>
        /// <param name="progressCallback">Callback for progress updates</param>
        /// <param name="completionCallback">Callback when scan completes</param>
        void RunScanAsync(
            const std::string& startIp,
            const std::string& endIp,
            const std::vector<uint16_t>& ports,
            std::function<void(size_t current, size_t total, const std::string& status)> progressCallback,
            std::function<void()> completionCallback
        );

        /// <summary>
        /// Gets the current scan result (thread-safe).
        /// </summary>
        netlens::ScanResult GetScanResult() const;

        /// <summary>
        /// Gets a formatted string representation of the scan results for display.
        /// </summary>
        std::wstring GetFormattedResults() const;

        /// <summary>
        /// Checks if a scan is currently running.
        /// </summary>
        bool IsScanRunning() const { return m_isScanning.load(); }

    private:
        std::unique_ptr<netlens::Scanner> m_scanner;
        netlens::ScanResult m_scanResult;
        mutable std::mutex m_resultMutex;
        std::atomic<bool> m_isScanning;
    };
}
