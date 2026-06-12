#include "packet_throttler.h"
#include <iostream>
#include <algorithm>

PacketThrottler::PacketThrottler(HANDLE divert_handle)
    : divert_handle_(divert_handle), running_(false)
{
}

PacketThrottler::~PacketThrottler()
{
    Stop();
}

void PacketThrottler::Start()
{
    if (running_)
    {
        return;
    }
    running_ = true;
    worker_thread_ = std::thread(&PacketThrottler::WorkerThreadFunc, this);
}

void PacketThrottler::Stop()
{
    if (!running_)
    {
        return;
    }
    running_ = false;
    if (worker_thread_.joinable())
    {
        worker_thread_.join();
    }

    // Flush any remaining packets in the queues to prevent memory leaks
    std::lock_guard<std::mutex> lock(mtx_);
    buckets_.clear();
}

void PacketThrottler::QueuePacket(
    const ConnectionKey& conn_key,
    const uint8_t* packet,
    UINT packet_len,
    const WINDIVERT_ADDRESS& addr)
{
    std::lock_guard<std::mutex> lock(mtx_);

    auto it = buckets_.find(conn_key);
    if (it == buckets_.end())
    {
        TokenBucket bucket = {};
        bucket.tokens = 8192.0; // Start with full initial burst capacity (8KB)
        bucket.last_fill_time = GetTickCount64();
        buckets_[conn_key] = bucket;
        it = buckets_.find(conn_key);
    }

    // Limit queue size to 200 packets to prevent excessive memory usage
    // Dropping packets triggers TCP congestion control to automatically throttle sender
    if (it->second.packet_queue.size() > 200)
    {
        return;
    }

    DeferredPacket pkt;
    pkt.data.assign(packet, packet + packet_len);
    pkt.addr = addr;
    it->second.packet_queue.push(pkt);
}

void PacketThrottler::WorkerThreadFunc()
{
    while (running_)
    {
        bool has_pending_packets = false;
        ULONGLONG current_time = GetTickCount64();

        {
            std::lock_guard<std::mutex> lock(mtx_);
            for (auto it = buckets_.begin(); it != buckets_.end();)
            {
                TokenBucket& bucket = it->second;

                // Calculate elapsed time and add tokens
                double elapsed_ms = static_cast<double>(current_time - bucket.last_fill_time);
                bucket.last_fill_time = current_time;

                // Fill rate: 30kbps = 3,750 bytes/second = 3.75 bytes/millisecond
                double new_tokens = elapsed_ms * 3.75;
                bucket.tokens += new_tokens;

                // Burst capacity cap (8KB)
                if (bucket.tokens > 8192.0)
                {
                    bucket.tokens = 8192.0;
                }

                // Dispatch packets from the queue while we have tokens
                while (!bucket.packet_queue.empty())
                {
                    const auto& pkt = bucket.packet_queue.front();
                    size_t pkt_len = pkt.data.size();

                    if (bucket.tokens >= static_cast<double>(pkt_len))
                    {
                        bucket.tokens -= static_cast<double>(pkt_len);

                        // Reinject the packet
                        WinDivertSend(
                            divert_handle_,
                            pkt.data.data(),
                            static_cast<UINT>(pkt_len),
                            nullptr,
                            &pkt.addr);

                        bucket.packet_queue.pop();
                    }
                    else
                    {
                        has_pending_packets = true;
                        break; // Order preservation: wait until this packet can be sent
                    }
                }

                // If connection is dead and has no queued packets, clean it up
                // We prune after 10 seconds of inactivity to keep memory footprint low
                if (bucket.packet_queue.empty() && (current_time - bucket.last_fill_time > 10000))
                {
                    it = buckets_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        // Sleep briefly to conserve CPU resources while rate-limiting
        if (has_pending_packets)
        {
            Sleep(5);
        }
        else
        {
            Sleep(20);
        }
    }
}
