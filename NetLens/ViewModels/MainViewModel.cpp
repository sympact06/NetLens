// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "pch.h"
#include "MainViewModel.h"
#include <sstream>
#include <thread>

namespace NetLens::ViewModels
{
    MainViewModel::MainViewModel()
        : m_scanner(std::make_unique<netlens::Scanner>())
        , m_scanResult()
        , m_isScanning(false)
    {
    }

    MainViewModel::~MainViewModel() = default;

    void MainViewModel::RunScanAsync(
        const std::string& startIp,
        const std::string& endIp,
        const std::vector<uint16_t>& ports,
        std::function<void(size_t current, size_t total, const std::string& status)> progressCallback,
        std::function<void()> completionCallback)
    {
        // Don't start a new scan if one is already running
        if (m_isScanning.exchange(true)) {
            return;
        }

        // Launch scan on a background thread
        std::thread scanThread([this, startIp, endIp, ports, progressCallback, completionCallback]() {
            try {
                // Create scan settings from user input
                netlens::ScanSettings settings;
                settings.start_ip = startIp;
                settings.end_ip = endIp;
                settings.ports = ports;
                settings.timeout_ms = 500;
                settings.max_concurrency = 50;

                // Calculate approximate total operations for progress
                size_t estimated_hosts = 254;  // Rough estimate
                size_t total_operations = estimated_hosts * ports.size();
                size_t completed_operations = 0;

                // Execute scan with progress callback
                netlens::ScanResult result = m_scanner->scan(settings, 
                    [&](const netlens::ScanProgress& progress) {
                        // Calculate overall progress
                        completed_operations = 
                            (progress.completed_hosts * ports.size()) + 
                            progress.completed_ports;

                        // Format status message
                        std::ostringstream status;
                        status << "Scanning " << progress.current_ip 
                               << " (Host " << (progress.completed_hosts + 1) 
                               << "/" << progress.total_hosts << ")";

                        // Call UI progress callback
                        if (progressCallback) {
                            progressCallback(completed_operations, total_operations, status.str());
                        }
                    });

                // Store result (thread-safe)
                {
                    std::lock_guard<std::mutex> lock(m_resultMutex);
                    m_scanResult = std::move(result);
                }
            }
            catch (const std::exception& ex) {
                // Handle scan errors
                std::lock_guard<std::mutex> lock(m_resultMutex);
                m_scanResult = netlens::ScanResult();
                
                netlens::HostResult error_host;
                error_host.address = "ERROR";
                error_host.is_alive = false;
                
                netlens::PortResult error_port;
                error_port.port = 0;
                error_port.is_open = false;
                error_port.banner = std::string("Scan error: ") + ex.what();
                error_host.ports.push_back(error_port);
                
                m_scanResult.hosts.push_back(error_host);
            }

            // Mark scan as complete
            m_isScanning.store(false);

            // Call completion callback
            if (completionCallback) {
                completionCallback();
            }
        });

        // Detach thread so it runs independently
        scanThread.detach();
    }

    netlens::ScanResult MainViewModel::GetScanResult() const
    {
        std::lock_guard<std::mutex> lock(m_resultMutex);
        return m_scanResult;
    }

    std::wstring MainViewModel::GetFormattedResults() const
    {
        std::lock_guard<std::mutex> lock(m_resultMutex);
        std::wstringstream ss;
        
        if (m_scanResult.hosts.empty())
        {
            ss << L"No scan results available. Configure your scan and click 'Run Network Scan' to start.";
            return ss.str();
        }

        // Check for error result
        if (!m_scanResult.hosts.empty() && m_scanResult.hosts[0].address == "ERROR") {
            ss << L"SCAN ERROR:\n";
            if (!m_scanResult.hosts[0].ports.empty()) {
                ss << m_scanResult.hosts[0].ports[0].banner.c_str() << L"\n";
            }
            return ss.str();
        }

        ss << L"=== NetLens Scan Results ===\n\n";
        ss << L"IP Range: " << m_scanResult.settings.start_ip.c_str() 
           << L" - " << m_scanResult.settings.end_ip.c_str() << L"\n";
        ss << L"Ports Scanned: ";
        for (size_t i = 0; i < m_scanResult.settings.ports.size(); ++i) {
            ss << m_scanResult.settings.ports[i];
            if (i < m_scanResult.settings.ports.size() - 1) {
                ss << L", ";
            }
        }
        ss << L"\n";
        ss << L"Timeout: " << m_scanResult.settings.timeout_ms << L" ms\n";
        ss << L"Total Hosts Scanned: " << m_scanResult.hosts.size() << L"\n\n";

        // Count alive hosts
        size_t aliveCount = 0;
        for (const auto& host : m_scanResult.hosts) {
            if (host.is_alive) ++aliveCount;
        }
        ss << L"Alive Hosts: " << aliveCount << L"\n";
        ss << L"Dead Hosts: " << (m_scanResult.hosts.size() - aliveCount) << L"\n\n";

        ss << L"--- Detailed Results ---\n\n";

        // Display all hosts with banners
        for (const auto& host : m_scanResult.hosts)
        {
            ss << L"Host: " << host.address.c_str() 
               << (host.is_alive ? L" [ALIVE]" : L" [DOWN]") << L"\n";
            
            if (host.is_alive && !host.ports.empty())
            {
                ss << L"  Open Ports:\n";
                for (const auto& port : host.ports)
                {
                    if (port.is_open)
                    {
                        ss << L"    • Port " << port.port;
                        
                        // Show banner if available
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
