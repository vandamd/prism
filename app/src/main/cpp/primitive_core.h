#pragma once

#include <android/binder_ibinder.h>

#include <cstdint>
#include <memory>
#include <string>

namespace prism::primitive {

using EventSink = void (*)(void* context, std::uint64_t elapsed_nanoseconds,
                           const char* stage, const char* detail);

struct Configuration {
    const char* binder_path = "/dev/binder";
};

struct Result {
    bool passed = false;
    std::uint64_t duration_nanoseconds = 0;
    std::string stage;
    std::string detail;
};

Result probe(const Configuration& configuration, EventSink sink,
             void* sink_context);

Result probe_broker(EventSink sink, void* sink_context);

struct DeathObservation {
    bool passed = false;
    bool died = false;
    bool unlinked = false;
    binder_status_t link_status = STATUS_UNKNOWN_ERROR;
    std::uint64_t duration_nanoseconds = 0;
};

class BinderDeathBarrier {
public:
    static std::unique_ptr<BinderDeathBarrier> arm(
            AIBinder* binder, binder_status_t* status);

    ~BinderDeathBarrier();

    BinderDeathBarrier(const BinderDeathBarrier&) = delete;
    BinderDeathBarrier& operator=(const BinderDeathBarrier&) = delete;

    DeathObservation wait(std::uint64_t timeout_milliseconds);

private:
    struct State;

    static void binder_died(void* cookie);
    static void binder_unlinked(void* cookie);

    BinderDeathBarrier(AIBinder* binder, AIBinder_DeathRecipient* recipient,
                       std::shared_ptr<State> state,
                       binder_status_t link_status);

    AIBinder* binder_;
    AIBinder_DeathRecipient* recipient_;
    std::shared_ptr<State> state_;
    binder_status_t link_status_;
};

class ProcessLifetimeGuard {
public:
    static std::unique_ptr<ProcessLifetimeGuard> arm(int pid, int* error);

    ~ProcessLifetimeGuard();

    ProcessLifetimeGuard(const ProcessLifetimeGuard&) = delete;
    ProcessLifetimeGuard& operator=(const ProcessLifetimeGuard&) = delete;

    bool alive(int* error) const;

private:
    explicit ProcessLifetimeGuard(int descriptor);

    int descriptor_;
};

}  // namespace prism::primitive
