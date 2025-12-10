// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "pch.h"
#include "MainWindow.xaml.h"
#if __has_include("MainWindow.g.cpp")
#include "MainWindow.g.cpp"
#endif
#include "ViewModels/MainViewModel.h"
#include <netlens/JsonExporter.h>
#include <sstream>
#include <regex>

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::NetLens::implementation
{
    MainWindow::MainWindow()
        : m_viewModel(std::make_unique<::NetLens::ViewModels::MainViewModel>())
    {
        InitializeComponent();
        
        // Get the dispatcher queue for UI thread updates
        m_dispatcherQueue = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
    }

    MainWindow::~MainWindow() = default;

    bool MainWindow::ValidateInputs(std::string& startIp, std::string& endIp, std::vector<uint16_t>& ports)
    {
        // Get input values
        startIp = winrt::to_string(StartIpTextBox().Text());
        endIp = winrt::to_string(EndIpTextBox().Text());
        std::string portsStr = winrt::to_string(PortsTextBox().Text());

        // Validate IP addresses (simple regex)
        std::regex ipPattern(R"(^(\d{1,3}\.){3}\d{1,3}$)");
        if (!std::regex_match(startIp, ipPattern) || !std::regex_match(endIp, ipPattern)) {
            StatusTextBlock().Text(L"Invalid IP address format!");
            return false;
        }

        // Parse ports
        ports.clear();
        std::istringstream iss(portsStr);
        std::string token;
        while (std::getline(iss, token, ',')) {
            // Trim whitespace
            token.erase(0, token.find_first_not_of(" \t"));
            token.erase(token.find_last_not_of(" \t") + 1);
            
            try {
                int port = std::stoi(token);
                if (port < 1 || port > 65535) {
                    StatusTextBlock().Text(L"Port number out of range (1-65535)!");
                    return false;
                }
                ports.push_back(static_cast<uint16_t>(port));
            }
            catch (...) {
                StatusTextBlock().Text(L"Invalid port number format!");
                return false;
            }
        }

        if (ports.empty()) {
            StatusTextBlock().Text(L"At least one port must be specified!");
            return false;
        }

        return true;
    }

    void MainWindow::OnRunScanClick(winrt::Windows::Foundation::IInspectable const&,
                                     winrt::Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        // Check if scan is already running
        if (m_viewModel->IsScanRunning()) {
            return;
        }

        // Validate and get inputs
        std::string startIp, endIp;
        std::vector<uint16_t> ports;
        if (!ValidateInputs(startIp, endIp, ports)) {
            return;
        }

        // Disable controls
        RunScanButton().IsEnabled(false);
        ExportJsonButton().IsEnabled(false);
        StartIpTextBox().IsEnabled(false);
        EndIpTextBox().IsEnabled(false);
        PortsTextBox().IsEnabled(false);

        // Show progress bar
        auto progressBar = ScanProgressBar();
        if (progressBar) {
            progressBar.Visibility(Visibility::Visible);
            progressBar.IsIndeterminate(false);
            progressBar.Value(0);
        }

        // Hide summary
        SummaryBorder().Visibility(Visibility::Collapsed);

        // Clear previous results
        auto resultsTextBlock = ResultsTextBlock();
        if (resultsTextBlock) {
            resultsTextBlock.Text(L"Initializing scan...");
        }

        // Start async scan with user configuration
        m_viewModel->RunScanAsync(
            startIp, endIp, ports,
            // Progress callback (called from background thread)
            [this](size_t current, size_t total, const std::string& status) {
                // Marshal to UI thread
                if (m_dispatcherQueue) {
                    m_dispatcherQueue.TryEnqueue([this, current, total, status]() {
                        UpdateProgress(current, total, status);
                    });
                }
            },
            // Completion callback (called from background thread)
            [this]() {
                // Marshal to UI thread
                if (m_dispatcherQueue) {
                    m_dispatcherQueue.TryEnqueue([this]() {
                        OnScanComplete();
                    });
                }
            }
        );
    }

    void MainWindow::OnExportJsonClick(winrt::Windows::Foundation::IInspectable const&,
                                        winrt::Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        // Get scan result
        auto result = m_viewModel->GetScanResult();
        
        if (result.hosts.empty()) {
            StatusTextBlock().Text(L"No scan results to export!");
            return;
        }

        // Generate filename with timestamp
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &time);
        
        char filename[256];
        std::strftime(filename, sizeof(filename), "netlens_scan_%Y%m%d_%H%M%S.json", &tm);
        
        // Save to file (in current directory for now)
        bool success = netlens::JsonExporter::saveToFile(result, filename, true);
        
        if (success) {
            std::wstring message = L"Scan results exported to: ";
            message += std::wstring(filename, filename + strlen(filename));
            StatusTextBlock().Text(message);
        } else {
            StatusTextBlock().Text(L"Failed to export JSON file!");
        }
    }

    void MainWindow::UpdateProgress(size_t current, size_t total, const std::string& status)
    {
        // Update progress bar
        auto progressBar = ScanProgressBar();
        if (progressBar && total > 0) {
            double percentage = (static_cast<double>(current) / static_cast<double>(total)) * 100.0;
            progressBar.Value(percentage);
        }

        // Update status text
        auto statusText = StatusTextBlock();
        if (statusText) {
            std::wstring wstatus(status.begin(), status.end());
            statusText.Text(wstatus);
        }
    }

    void MainWindow::OnScanComplete()
    {
        // Re-enable controls
        RunScanButton().IsEnabled(true);
        ExportJsonButton().IsEnabled(true);
        StartIpTextBox().IsEnabled(true);
        EndIpTextBox().IsEnabled(true);
        PortsTextBox().IsEnabled(true);

        // Hide progress bar
        auto progressBar = ScanProgressBar();
        if (progressBar) {
            progressBar.Visibility(Visibility::Collapsed);
        }

        // Clear status
        auto statusText = StatusTextBlock();
        if (statusText) {
            statusText.Text(L"Scan complete!");
        }

        // Update the UI to display results
        UpdateResultsDisplay();
        UpdateSummary();
    }

    void MainWindow::UpdateResultsDisplay()
    {
        // Get the formatted results from the view model
        auto results = m_viewModel->GetFormattedResults();
        
        // Find the TextBlock and update its text
        auto resultsTextBlock = ResultsTextBlock();
        if (resultsTextBlock)
        {
            resultsTextBlock.Text(results);
        }
    }

    void MainWindow::UpdateSummary()
    {
        // Get scan result
        auto result = m_viewModel->GetScanResult();
        
        if (result.hosts.empty()) {
            SummaryBorder().Visibility(Visibility::Collapsed);
            return;
        }

        // Count alive hosts
        size_t aliveCount = 0;
        for (const auto& host : result.hosts) {
            if (host.is_alive) ++aliveCount;
        }

        // Update summary
        TotalHostsText().Text(L"Total Hosts: " + winrt::to_hstring(result.hosts.size()));
        AliveHostsText().Text(L"Alive: " + winrt::to_hstring(aliveCount));
        DeadHostsText().Text(L"Down: " + winrt::to_hstring(result.hosts.size() - aliveCount));

        // Show summary
        SummaryBorder().Visibility(Visibility::Visible);
    }
}
