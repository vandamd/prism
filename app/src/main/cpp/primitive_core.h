#pragma once

#include <android/binder_ibinder.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

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

Result probe_route(const char* service_template_path,
                   const char* start_template_path, EventSink sink,
                   void* sink_context);

struct VictimToken {
    std::uint64_t pointer = 0;
    std::uint64_t cookie = 0;
};

struct HolderReleaseReceipt {
    int contexts = 0;
    int handles = 0;
    int death_notifications = 0;
    int mappings = 0;
    int descriptors = 0;
};

class HolderCohort {
public:
    static std::unique_ptr<HolderCohort> create(
            const char* service_template_path,
            const char* start_template_path,
            int holder_count,
            std::int32_t index_sentinel,
            Result* result,
            EventSink sink = nullptr,
            void* sink_context = nullptr);

    ~HolderCohort();

    HolderCohort(const HolderCohort&) = delete;
    HolderCohort& operator=(const HolderCohort&) = delete;

    Result receive(int holder_count, int fixed_refs_per_holder,
                   std::int32_t expected_proof, int death_object_index);
    Result release_handles(int expected_handles, int expected_deaths);
    Result release(HolderReleaseReceipt* receipt);

private:
    struct State;

    explicit HolderCohort(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

class VictimCohort {
public:
    static std::unique_ptr<VictimCohort> create(
            const char* service_template_path,
            const char* start_template_path,
            int victim_count,
            Result* result,
            EventSink sink = nullptr,
            void* sink_context = nullptr);

    ~VictimCohort();

    VictimCohort(const VictimCohort&) = delete;
    VictimCohort& operator=(const VictimCohort&) = delete;

    Result collect(std::vector<VictimToken>* tokens);
    Result retire(int victim, std::uint64_t settle_microseconds);
    Result release();

private:
    struct State;

    explicit VictimCohort(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

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
