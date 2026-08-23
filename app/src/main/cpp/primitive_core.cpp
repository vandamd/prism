#include "primitive_core.h"

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>

namespace prism::primitive {
namespace {

constexpr std::size_t kBinderMappingSize = 1024 * 1024;

std::uint64_t boot_nanoseconds() {
    timespec value {};
    if (clock_gettime(CLOCK_BOOTTIME, &value) != 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(value.tv_sec) * 1000000000ULL +
            static_cast<std::uint64_t>(value.tv_nsec);
}

void emit(EventSink sink, void* context, std::uint64_t started,
          const char* stage, const std::string& detail) {
    if (sink != nullptr) {
        sink(context, boot_nanoseconds() - started, stage, detail.c_str());
    }
}

Result failure(std::uint64_t started, const char* stage, int error,
               EventSink sink, void* context) {
    Result result;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.stage = stage;
    result.detail = std::string("errno=") + std::to_string(error) +
            " message=" + std::strerror(error);
    emit(sink, context, started, stage, result.detail);
    return result;
}

void* broker_create(void* arguments) {
    return arguments;
}

void broker_destroy(void*) {}

binder_status_t broker_transaction(AIBinder*, transaction_code_t,
                                   const AParcel*, AParcel*) {
    return STATUS_UNKNOWN_TRANSACTION;
}

}  // namespace

struct BinderDeathBarrier::State {
    std::mutex mutex;
    std::condition_variable changed;
    bool died = false;
    bool unlinked = false;
};

void BinderDeathBarrier::binder_died(void* cookie) {
    auto& state = *static_cast<std::shared_ptr<State>*>(cookie);
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->died = true;
    }
    state->changed.notify_all();
}

void BinderDeathBarrier::binder_unlinked(void* cookie) {
    std::unique_ptr<std::shared_ptr<State>> state(
            static_cast<std::shared_ptr<State>*>(cookie));
    {
        std::lock_guard<std::mutex> lock((*state)->mutex);
        (*state)->unlinked = true;
    }
    (*state)->changed.notify_all();
}

BinderDeathBarrier::BinderDeathBarrier(
        AIBinder* binder, AIBinder_DeathRecipient* recipient,
        std::shared_ptr<State> state, binder_status_t link_status)
    : binder_(binder),
      recipient_(recipient),
      state_(std::move(state)),
      link_status_(link_status) {}

std::unique_ptr<BinderDeathBarrier> BinderDeathBarrier::arm(
        AIBinder* binder, binder_status_t* status) {
    if (binder == nullptr || AIBinder_isRemote(binder) == false) {
        if (status != nullptr) {
            *status = STATUS_INVALID_OPERATION;
        }
        return nullptr;
    }
    auto state = std::make_shared<State>();
    auto* cookie = new (std::nothrow) std::shared_ptr<State>(state);
    if (cookie == nullptr) {
        if (status != nullptr) {
            *status = STATUS_NO_MEMORY;
        }
        return nullptr;
    }
    AIBinder_DeathRecipient* recipient =
            AIBinder_DeathRecipient_new(binder_died);
    if (recipient == nullptr) {
        delete cookie;
        if (status != nullptr) {
            *status = STATUS_NO_MEMORY;
        }
        return nullptr;
    }
    AIBinder_DeathRecipient_setOnUnlinked(recipient, binder_unlinked);
    AIBinder_incStrong(binder);
    binder_status_t link_status = AIBinder_linkToDeath(
            binder, recipient, cookie);
    if (status != nullptr) {
        *status = link_status;
    }
    if (link_status != STATUS_OK) {
        AIBinder_DeathRecipient_delete(recipient);
        AIBinder_decStrong(binder);
        return nullptr;
    }
    return std::unique_ptr<BinderDeathBarrier>(
            new BinderDeathBarrier(
                    binder, recipient, std::move(state), link_status));
}

BinderDeathBarrier::~BinderDeathBarrier() {
    AIBinder_DeathRecipient_delete(recipient_);
    AIBinder_decStrong(binder_);
}

DeathObservation BinderDeathBarrier::wait(
        std::uint64_t timeout_milliseconds) {
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started +
            std::chrono::milliseconds(timeout_milliseconds);
    std::unique_lock<std::mutex> lock(state_->mutex);
    state_->changed.wait_until(lock, deadline, [&] {
        return state_->died && state_->unlinked;
    });
    DeathObservation observation;
    observation.died = state_->died;
    observation.unlinked = state_->unlinked;
    observation.passed = observation.died && observation.unlinked;
    observation.link_status = link_status_;
    observation.duration_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - started).count();
    return observation;
}

ProcessLifetimeGuard::ProcessLifetimeGuard(int descriptor)
    : descriptor_(descriptor) {}

std::unique_ptr<ProcessLifetimeGuard> ProcessLifetimeGuard::arm(
        int pid, int* error) {
    if (pid <= 0) {
        if (error != nullptr) {
            *error = EINVAL;
        }
        return nullptr;
    }
    errno = 0;
    int descriptor = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
    if (descriptor < 0) {
        if (error != nullptr) {
            *error = errno;
        }
        return nullptr;
    }
    if (error != nullptr) {
        *error = 0;
    }
    return std::unique_ptr<ProcessLifetimeGuard>(
            new ProcessLifetimeGuard(descriptor));
}

ProcessLifetimeGuard::~ProcessLifetimeGuard() {
    close(descriptor_);
}

bool ProcessLifetimeGuard::alive(int* error) const {
    pollfd descriptor {descriptor_, POLLIN, 0};
    errno = 0;
    int result = poll(&descriptor, 1, 0);
    if (result == 0) {
        if (error != nullptr) {
            *error = 0;
        }
        return true;
    }
    if (error != nullptr) {
        *error = result < 0 ? errno : 0;
    }
    return false;
}

Result probe(const Configuration& configuration, EventSink sink,
             void* sink_context) {
    const std::uint64_t started = boot_nanoseconds();
    emit(sink, sink_context, started, "start", "mode=probe");

    utsname system {};
    if (uname(&system) != 0) {
        return failure(started, "uname", errno, sink, sink_context);
    }
    char identity[512];
    std::snprintf(identity, sizeof(identity),
                  "machine=%s release=%s pid=%d uid=%d",
                  system.machine, system.release, getpid(), getuid());
    emit(sink, sink_context, started, "identity", identity);

    int binder = open(configuration.binder_path, O_RDWR | O_CLOEXEC);
    if (binder < 0) {
        return failure(started, "binder-open", errno, sink, sink_context);
    }
    emit(sink, sink_context, started, "binder-open", "status=pass");

    binder_version version {};
    if (ioctl(binder, BINDER_VERSION, &version) != 0) {
        int saved_errno = errno;
        close(binder);
        return failure(started, "binder-version", saved_errno, sink,
                       sink_context);
    }
    char version_detail[64];
    std::snprintf(version_detail, sizeof(version_detail), "protocol=%d",
                  version.protocol_version);
    emit(sink, sink_context, started, "binder-version", version_detail);

    void* mapping = mmap(nullptr, kBinderMappingSize, PROT_READ,
                         MAP_PRIVATE | MAP_NORESERVE, binder, 0);
    if (mapping == MAP_FAILED) {
        int saved_errno = errno;
        close(binder);
        return failure(started, "binder-map", saved_errno, sink,
                       sink_context);
    }
    emit(sink, sink_context, started, "binder-map", "status=pass bytes=1048576");

    bool unmapped = munmap(mapping, kBinderMappingSize) == 0;
    bool closed = close(binder) == 0;
    if (!unmapped || !closed) {
        return failure(started, "binder-close", errno, sink, sink_context);
    }

    Result result;
    result.passed = true;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.stage = "probe-complete";
    result.detail = "status=pass";
    emit(sink, sink_context, started, result.stage.c_str(),
         result.detail);
    return result;
}

Result probe_broker(EventSink sink, void* sink_context) {
    const std::uint64_t started = boot_nanoseconds();
    emit(sink, sink_context, started, "start", "mode=broker-probe");

    AIBinder_Class* binder_class = AIBinder_Class_define(
            "com.vandam.prism.PrimitiveProbe", broker_create,
            broker_destroy, broker_transaction);
    if (binder_class == nullptr) {
        return failure(started, "broker-class", EIO, sink, sink_context);
    }
    AIBinder* binder = AIBinder_new(binder_class, nullptr);
    if (binder == nullptr) {
        return failure(started, "broker-node", EIO, sink, sink_context);
    }

    std::string name = "prism.primitive.probe." +
            std::to_string(getpid());
    using AddService = binder_status_t (*)(AIBinder*, const char*);
    auto add_service = reinterpret_cast<AddService>(
            dlsym(RTLD_DEFAULT, "AServiceManager_addService"));
    if (add_service == nullptr) {
        AIBinder_decStrong(binder);
        return failure(started, "broker-symbol", ENOSYS, sink,
                       sink_context);
    }
    binder_status_t status = add_service(binder, name.c_str());
    AIBinder_decStrong(binder);

    char detail[256];
    std::snprintf(detail, sizeof(detail), "status=%d name=%s",
                  status, name.c_str());
    emit(sink, sink_context, started, "broker-register", detail);

    Result result;
    result.passed = status == STATUS_OK;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.stage = result.passed ? "broker-probe-complete" :
            "broker-register";
    result.detail = detail;
    return result;
}

}  // namespace prism::primitive
