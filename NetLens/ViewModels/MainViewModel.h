// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <memory>
#include <string>
#include <vector>
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
        /// Executes a test scan with hard-coded settings (Phase 0).
        /// </summary>
        void RunTestScan();

        /// <summary>
        /// Gets the current scan result.
        /// </summary>
        const netlens::ScanResult& GetScanResult() const { return m_scanResult; }

        /// <summary>
        /// Gets a formatted string representation of the scan results for display.
        /// </summary>
        std::wstring GetFormattedResults() const;

    private:
        std::unique_ptr<netlens::Scanner> m_scanner;
        netlens::ScanResult m_scanResult;
    };
}
