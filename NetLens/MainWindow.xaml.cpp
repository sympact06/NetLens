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
    }

    MainWindow::~MainWindow() = default;

    void MainWindow::OnRunTestScanClick(winrt::Windows::Foundation::IInspectable const&,
                                         winrt::Microsoft::UI::Xaml::RoutedEventArgs const&)
    {
        // Execute the test scan via the view model
        m_viewModel->RunTestScan();
        
        // Update the UI to display results
        UpdateResultsDisplay();
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
}
