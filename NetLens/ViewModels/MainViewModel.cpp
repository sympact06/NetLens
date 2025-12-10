// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "pch.h"
#include "MainViewModel.h"
#include <sstream>

namespace NetLens::ViewModels
{
    MainViewModel::MainViewModel()
        : m_scanner(std::make_unique<netlens::Scanner>())
        , m_scanResult()
    {
    }

    MainViewModel::~MainViewModel() = default;

    void MainViewModel::RunTestScan()
    {
        // Phase 0: Create hard-coded test settings
        netlens::ScanSettings settings;
        settings.start_ip = "192.168.1.1";
        settings.end_ip = "192.168.1.254";
        settings.ports = { 22, 80, 443, 445, 3389 };
        settings.timeout_ms = 1000;
        settings.max_concurrency = 100;

        // Execute the scan (returns placeholder data in Phase 0)
        m_scanResult = m_scanner->scan(settings);
    }

    std::wstring MainViewModel::GetFormattedResults() const
    {
        std::wstringstream ss;
        
        if (m_scanResult.hosts.empty())
        {
            ss << L"No scan results available. Click 'Run Test Scan' to start.";
            return ss.str();
        }

        ss << L"Scan Results:\n";
        ss << L"IP Range: " << m_scanResult.settings.start_ip.c_str() 
           << L" - " << m_scanResult.settings.end_ip.c_str() << L"\n";
        ss << L"Found " << m_scanResult.hosts.size() << L" host(s)\n\n";

        for (const auto& host : m_scanResult.hosts)
        {
            ss << L"Host: " << host.address.c_str() 
               << (host.is_alive ? L" (ALIVE)" : L" (DOWN)") << L"\n";
            
            if (!host.ports.empty())
            {
                ss << L"  Open Ports:\n";
                for (const auto& port : host.ports)
                {
                    if (port.is_open)
                    {
                        ss << L"    Port " << port.port;
                        if (!port.banner.empty())
                        {
                            ss << L" - " << port.banner.c_str();
                        }
                        ss << L"\n";
                    }
                }
            }
            ss << L"\n";
        }

        return ss.str();
    }
}
