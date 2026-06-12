#ifndef PACKET_THROTTLER_H
#define PACKET_THROTTLER_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <map>
#include <cstdint>
#include "windivert.h"
#include "connection_tracker.h"

// Represents a packet deferred for rate-limiting
struct DeferredPacket
{
    std::vector<uint8_t> data;
    WINDIVERT_ADDRESS addr;
};

// Manages the token bucket state and queue for a throttled connection
struct TokenBucket
{
    double tokens;
    ULONGLONG last_fill_time;
    std::queue<DeferredPacket> packet_queue;
};

class PacketThrottler
{
public:
    PacketThrottler(HANDLE divert_handle);
    ~PacketThrottler();

    void Start();
    void Stop();

    // Queues a packet for a connection to be throttled.
    // If the queue is full, the packet is dropped to leverage TCP congestion control.
    void QueuePacket(
        const ConnectionKey& conn_key,
        const uint8_t* packet,
        UINT packet_len,
        const WINDIVERT_ADDRESS& addr);

    // Retrieves the total number of bytes throttled (rate-limited)
    uint64_t GetBytesThrottled() const;

private:
    void WorkerThreadFunc();

    HANDLE divert_handle_;
    std::thread worker_thread_;
    volatile bool running_;

    mutable std::mutex mtx_;
    std::map<ConnectionKey, TokenBucket> buckets_;
    uint64_t bytes_throttled_ = 0;
};

#endif // PACKET_THROTTLER_H
