// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "AsyncScanEngine.h"
#include "IpRange.h"
#include "BannerGrabber.h"
#include <asio.hpp>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif

namespace netlens::internal {

// Implementation details hidden from header
struct AsyncScanEngine::Impl {
    asio::io_context io_context;
    std::unique_ptr<asio::io_context::work> work_guard;
    std::vector<std::thread> thread_pool;
    std::mutex results_mutex;
    std::condition_variable completion_cv;
    std::atomic<size_t> pending_operations{0};
    std::atomic<size_t> completed_hosts{0};
    std::atomic<size_t> completed_ports{0};
    
    ProgressCallback progress_callback;
    ScanProgress current_progress;
    std::mutex progress_mutex;
    
    static constexpr size_t DEFAULT_MAX_PORTS_PER_HOST = 100;
    static constexpr size_t MIN_TIMEOUT_MS = 50;
    static constexpr size_t MAX_TIMEOUT_MS = 30000;

    void initThreadPool(size_t num_threads) {
        work_guard = std::make_unique<asio::io_context::work>(io_context);
        
        for (size_t i = 0; i < num_threads; ++i) {
            thread_pool.emplace_back([this]() {
                io_context.run();
            });
        }
    }

    void stopThreadPool() {
        work_guard.reset();
        io_context.stop();
        
        for (auto& thread : thread_pool) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        thread_pool.clear();
    }

    void updateProgress(const std::string& current_ip) {
        if (!progress_callback) return;

        std::lock_guard<std::mutex> lock(progress_mutex);
        current_progress.current_ip = current_ip;
        current_progress.completed_hosts = completed_hosts.load();
        current_progress.completed_ports = completed_ports.load();
        progress_callback(current_progress);
    }
};

AsyncScanEngine::AsyncScanEngine()
    : m_impl(std::make_unique<Impl>())
{
#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

AsyncScanEngine::~AsyncScanEngine() {
    if (m_impl) {
        m_impl->stopThreadPool();
    }
#ifdef _WIN32
    WSACleanup();
#endif
}

ScanResult AsyncScanEngine::executeScan(const ScanSettings& settings, ProgressCallback progressCallback) {
    // Setup progress tracking
    m_impl->progress_callback = progressCallback;
    m_impl->current_progress = ScanProgress();
    m_impl->completed_hosts.store(0);
    m_impl->completed_ports.store(0);

    // Enumerate IP addresses
    std::vector<std::string> addresses;
    try {
        addresses = IpRange::enumerate(settings.start_ip, settings.end_ip);
    } catch (const IpRangeException& e) {
        throw std::runtime_error(std::string("IP range error: ") + e.what());
    }

    m_impl->current_progress.total_hosts = addresses.size();
    m_impl->current_progress.total_ports = settings.ports.size() * addresses.size();

    // Determine thread pool size
    size_t num_threads = std::min(
        static_cast<size_t>(std::thread::hardware_concurrency()),
        static_cast<size_t>(8)
    );
    if (num_threads == 0) num_threads = 4;

    // Initialize thread pool
    m_impl->initThreadPool(num_threads);

    // Prepare result
    ScanResult result(settings);
    result.hosts.resize(addresses.size());

    // Determine concurrency limits
    size_t max_concurrent_hosts = settings.max_concurrency;
    if (max_concurrent_hosts == 0 || max_concurrent_hosts > addresses.size()) {
        max_concurrent_hosts = addresses.size();
    }

    // Semaphore for host-level concurrency
    std::mutex host_semaphore_mutex;
    std::condition_variable host_semaphore_cv;
    std::atomic<size_t> active_hosts{0};

    // Scan hosts with concurrency control
    for (size_t i = 0; i < addresses.size(); ++i) {
        const std::string& ip = addresses[i];
        HostResult& host_result = result.hosts[i];
        host_result.address = ip;
        host_result.is_alive = false;

        // Wait for slot if at max concurrent hosts
        {
            std::unique_lock<std::mutex> lock(host_semaphore_mutex);
            host_semaphore_cv.wait(lock, [&]() {
                return active_hosts.load() < max_concurrent_hosts;
            });
            active_hosts++;
            m_impl->pending_operations++;
        }

        // Post host scan to io_context
        asio::post(m_impl->io_context, [this, &settings, ip, &host_result, 
                                        &host_semaphore_mutex, &host_semaphore_cv, 
                                        &active_hosts]() {
            try {
                scanHost(ip, settings.ports, settings.timeout_ms, host_result);
                m_impl->completed_hosts++;
                m_impl->updateProgress(ip);
            } catch (...) {
                // Handle errors gracefully
            }

            // Release semaphore slot
            {
                std::lock_guard<std::mutex> lock(host_semaphore_mutex);
                active_hosts--;
                m_impl->pending_operations--;
            }
            host_semaphore_cv.notify_one();
            m_impl->completion_cv.notify_one();
        });
    }

    // Wait for all operations to complete
    {
        std::unique_lock<std::mutex> lock(host_semaphore_mutex);
        m_impl->completion_cv.wait(lock, [this]() {
            return m_impl->pending_operations.load() == 0;
        });
    }

    // Stop thread pool
    m_impl->stopThreadPool();

    return result;
}

void AsyncScanEngine::scanHost(const std::string& ip, const std::vector<uint16_t>& ports,
                                uint32_t timeout_ms, HostResult& result) {
    // Clamp timeout
    timeout_ms = std::max(static_cast<uint32_t>(Impl::MIN_TIMEOUT_MS),
                         std::min(static_cast<uint32_t>(Impl::MAX_TIMEOUT_MS), timeout_ms));

    // Prepare port results
    std::vector<PortResult> port_results(ports.size());
    std::atomic<size_t> completed_ports{0};
    std::mutex port_mutex;
    std::condition_variable port_cv;

    // Limit concurrent ports per host
    size_t max_concurrent_ports = std::min(ports.size(), Impl::DEFAULT_MAX_PORTS_PER_HOST);
    std::atomic<size_t> active_ports{0};

    // Scan each port
    for (size_t i = 0; i < ports.size(); ++i) {
        uint16_t port = ports[i];
        PortResult& port_result = port_results[i];
        port_result.port = port;
        port_result.is_open = false;

        // Wait for slot
        {
            std::unique_lock<std::mutex> lock(port_mutex);
            port_cv.wait(lock, [&]() {
                return active_ports.load() < max_concurrent_ports;
            });
            active_ports++;
        }

        // Create socket and endpoint
        auto socket = std::make_shared<asio::ip::tcp::socket>(m_impl->io_context);
        auto timer = std::make_shared<asio::steady_timer>(m_impl->io_context);
        auto endpoint = asio::ip::tcp::endpoint(
            asio::ip::make_address(ip), port);

        // Shared state for timeout handling
        auto timed_out = std::make_shared<std::atomic<bool>>(false);
        auto completed = std::make_shared<std::atomic<bool>>(false);

        // Set up timeout
        timer->expires_after(std::chrono::milliseconds(timeout_ms));
        timer->async_wait([socket, timed_out, completed](const asio::error_code& ec) {
            if (!ec && !completed->load()) {
                timed_out->store(true);
                asio::error_code ignore_ec;
                socket->close(ignore_ec);
            }
        });

        // Async connect
        socket->async_connect(endpoint, 
            [this, socket, timer, timed_out, completed, &port_result, ip, port, timeout_ms,
             &port_mutex, &port_cv, &active_ports, &completed_ports]
            (const asio::error_code& ec) {
                completed->store(true);
                timer->cancel();

                if (!ec && !timed_out->load()) {
                    port_result.is_open = true;
                    
                    // Attempt banner grabbing for open ports
                    try {
                        asio::error_code close_ec;
                        socket->close(close_ec);
                        
                        // Grab banner on a separate connection (synchronous)
                        port_result.banner = BannerGrabber::grabBanner(ip, port, timeout_ms / 2);
                    } catch (...) {
                        // Banner grabbing failed, but port is still open
                    }
                } else {
                    asio::error_code ignore_ec;
                    socket->close(ignore_ec);
                }

                // Update progress
                m_impl->completed_ports++;

                // Release slot
                {
                    std::lock_guard<std::mutex> lock(port_mutex);
                    active_ports--;
                    completed_ports++;
                }
                port_cv.notify_one();
            });
    }

    // Wait for all ports to complete
    {
        std::unique_lock<std::mutex> lock(port_mutex);
        port_cv.wait(lock, [&]() {
            return completed_ports.load() == ports.size();
        });
    }

    // Store results
    result.ports = std::move(port_results);

    // Determine if host is alive
    for (const auto& pr : result.ports) {
        if (pr.is_open) {
            result.is_alive = true;
            break;
        }
    }
}

} // namespace netlens::internal
