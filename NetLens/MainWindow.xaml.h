// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include "MainWindow.g.h"
#include <memory>

// Forward declare the ViewModel to avoid circular dependencies
namespace NetLens::ViewModels
{
    class MainViewModel;
}

namespace winrt::NetLens::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow();
        ~MainWindow(); // Destructor must be defined in .cpp where MainViewModel is complete

        void OnRunTestScanClick(winrt::Windows::Foundation::IInspectable const& sender, 
                                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

    private:
        std::unique_ptr<::NetLens::ViewModels::MainViewModel> m_viewModel;
        void UpdateResultsDisplay();
    };
}

namespace winrt::NetLens::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
