#include "primitive_core.h"

#include <cinttypes>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <signal.h>
#include <atomic>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

namespace {

void print_json_string(const char* value) {
    std::putchar('"');
    for (const unsigned char character :
         std::string(value == nullptr ? "" : value)) {
        if (character == '"' || character == '\\') {
            std::putchar('\\');
            std::putchar(character);
        } else if (character >= 0x20) {
            std::putchar(character);
        }
    }
    std::putchar('"');
}

void event(void*, std::uint64_t elapsed_nanoseconds, const char* stage,
           const char* detail) {
    std::fputs("{\"elapsed_ns\":", stdout);
    std::printf("%" PRIu64, elapsed_nanoseconds);
    std::fputs(",\"stage\":", stdout);
    print_json_string(stage);
    std::fputs(",\"detail\":", stdout);
    print_json_string(detail);
    std::fputs("}\n", stdout);
    std::fflush(stdout);
}

std::uint64_t monotonic_nanoseconds() {
    timespec value {};
    return clock_gettime(CLOCK_MONOTONIC, &value) == 0
            ? static_cast<std::uint64_t>(value.tv_sec) * 1'000'000'000ULL +
                    static_cast<std::uint64_t>(value.tv_nsec)
            : 0;
}

constexpr off_t kReSukiLoaderSize = 1'323'008;
constexpr off_t kReSukiExecutableSize = 4'215'752;
constexpr char kCompletionPrefix[] =
        "/data/local/tmp/lp3-ksud-completion.";
constexpr std::uint64_t kKernelLinkBase = UINT64_C(0xffffffc008000000);
constexpr std::uint64_t kKaslrAlignment = UINT64_C(0x200000);
constexpr std::uint64_t kActionDaemonReadyMagic =
        UINT64_C(0x4c50334452445931);
constexpr std::uint64_t kActionDaemonRequestMagic =
        UINT64_C(0x4c50334452455131);

struct ActionDaemonReady {
    std::uint64_t magic = kActionDaemonReadyMagic;
    std::int32_t pid = -1;
    std::int32_t tid = -1;
};

struct ActionDaemonRequest {
    std::uint64_t magic = 0;
    std::int32_t action = 0;
    std::int32_t manager_uid = -1;
    std::uint64_t kernel_base = 0;
    char completion_path[160] {};
};

using ReSukiProbeFunction = std::uint32_t (*)();
using ReSukiRelocateProbeFunction = int (*)(std::uint64_t);
using ReSukiStageFunction = int (*)(int, std::uint64_t);
using ReSukiLoadFunction = int (*)(std::uint32_t, int, int, std::uint64_t);

bool parse_decimal(const char* text, int minimum, int maximum, int* value) {
    if (text == nullptr || value == nullptr || *text == '\0') {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    long parsed = std::strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
            parsed < minimum || parsed > maximum) {
        return false;
    }
    *value = static_cast<int>(parsed);
    return true;
}

bool parse_kernel_base(const char* text, std::uint64_t* value) {
    if (text == nullptr || value == nullptr || *text == '\0') {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    unsigned long long parsed = std::strtoull(text, &end, 16);
    if (errno != 0 || end == text || *end != '\0' ||
            parsed < kKernelLinkBase ||
            (parsed & (kKaslrAlignment - 1)) != 0) {
        return false;
    }
    *value = static_cast<std::uint64_t>(parsed);
    return true;
}

bool valid_completion_path(const char* path) {
    if (path == nullptr ||
            std::strncmp(path, kCompletionPrefix,
                         sizeof(kCompletionPrefix) - 1) != 0) {
        return false;
    }
    const char* nonce = path + sizeof(kCompletionPrefix) - 1;
    if (std::strlen(nonce) != 32) {
        return false;
    }
    for (const char* cursor = nonce; *cursor != '\0'; ++cursor) {
        if (!((*cursor >= '0' && *cursor <= '9') ||
              (*cursor >= 'a' && *cursor <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool exact_shell_descriptor(int descriptor, off_t expected_size) {
    struct stat descriptor_stat {};
    return descriptor >= 0 && fstat(descriptor, &descriptor_stat) == 0 &&
            S_ISREG(descriptor_stat.st_mode) &&
            descriptor_stat.st_uid == 2000 &&
            descriptor_stat.st_gid == 2000 &&
            (descriptor_stat.st_mode & 0777) == 0755 &&
            descriptor_stat.st_size == expected_size;
}

bool exact_root_process() {
    if (syscall(SYS_getpid) != syscall(SYS_gettid)) {
        return false;
    }
    uid_t uids[3] {};
    gid_t gids[3] {};
    __user_cap_header_struct header {};
    __user_cap_data_struct data[2] {};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    if (syscall(SYS_getresuid, &uids[0], &uids[1], &uids[2]) != 0 ||
            syscall(SYS_getresgid, &gids[0], &gids[1], &gids[2]) != 0 ||
            syscall(SYS_capget, &header, data) != 0) {
        return false;
    }
    std::uint64_t capabilities =
            static_cast<std::uint64_t>(data[0].effective) |
            (static_cast<std::uint64_t>(data[1].effective) << 32U);
    return uids[0] == 0 && uids[1] == 0 && uids[2] == 0 &&
            gids[0] == 0 && gids[1] == 0 && gids[2] == 0 &&
            (capabilities & (UINT64_C(1) << 22U)) != 0;
}

int action_supervisor(int argc, char** argv) {
    if (argc != 9) {
        std::fputs("LP3_ACTION_SUPERVISOR_ERROR stage=arguments\n", stderr);
        return 64;
    }
    int action = 0;
    int manager_uid = 0;
    int loader_fd = -1;
    int module_fd = -1;
    int executable_fd = -1;
    std::uint64_t kernel_base = 0;
    bool arguments_valid =
            parse_decimal(argv[2], 1, 2, &action) &&
            parse_decimal(argv[3], 10'000, 19'999, &manager_uid) &&
            parse_decimal(argv[4], 0, 1'000'000, &loader_fd) &&
            parse_decimal(argv[5], 0, 1'000'000, &module_fd) &&
            parse_decimal(argv[6], 0, 1'000'000, &executable_fd) &&
            parse_kernel_base(argv[7], &kernel_base) &&
            valid_completion_path(argv[8]);
    if (!arguments_valid || !exact_root_process()) {
        std::fputs("LP3_ACTION_SUPERVISOR_ERROR stage=identity\n", stderr);
        return 65;
    }
    if (!exact_shell_descriptor(loader_fd, kReSukiLoaderSize) ||
            !exact_shell_descriptor(
                    executable_fd, kReSukiExecutableSize)) {
        std::fputs("LP3_ACTION_SUPERVISOR_ERROR stage=artefact-identity\n",
                   stderr);
        return 66;
    }
    struct stat module_stat {};
    if (fstat(module_fd, &module_stat) != 0 ||
            !S_ISREG(module_stat.st_mode)) {
        std::fputs("LP3_ACTION_SUPERVISOR_ERROR stage=module-fd\n", stderr);
        return 67;
    }

    char loader_path[64];
    int loader_path_length = std::snprintf(
            loader_path, sizeof(loader_path), "/proc/self/fd/%d", loader_fd);
    if (loader_path_length <= 0 ||
            loader_path_length >= static_cast<int>(sizeof(loader_path))) {
        return 68;
    }
    void* library = dlopen(loader_path, RTLD_NOW | RTLD_LOCAL);
    auto probe = library == nullptr ? nullptr :
            reinterpret_cast<ReSukiProbeFunction>(
                    dlsym(library, "lp3_resukisu_probe"));
    auto relocate = library == nullptr ? nullptr :
            reinterpret_cast<ReSukiRelocateProbeFunction>(
                    dlsym(library, "lp3_resukisu_relocate_probe"));
    auto stage = library == nullptr ? nullptr :
            reinterpret_cast<ReSukiStageFunction>(
                    dlsym(library, "lp3_resukisu_stage"));
    auto load = library == nullptr ? nullptr :
            reinterpret_cast<ReSukiLoadFunction>(
                    dlsym(library, "lp3_resukisu_load"));
    if (probe == nullptr || relocate == nullptr || stage == nullptr ||
            load == nullptr || probe() != UINT32_C(0x4c503352)) {
        std::fputs("LP3_ACTION_SUPERVISOR_ERROR stage=loader-symbols\n",
                   stderr);
        return 69;
    }
    if (action == 1) {
        std::fputs("LP3_ACTION_SUPERVISOR_PASS action=probe\n", stderr);
        return 0;
    }
    int relocation_result = relocate(kernel_base);
    int stage_result = relocation_result == 0
            ? stage(module_fd, kernel_base) : -1;
    if (relocation_result != 0 || stage_result != 0) {
        std::fprintf(
                stderr,
                "LP3_ACTION_SUPERVISOR_ERROR stage=module-stage"
                " relocation=%d result=%d\n",
                relocation_result, stage_result);
        return 70;
    }
    int load_result = load(
            static_cast<std::uint32_t>(manager_uid), STDERR_FILENO,
            module_fd, kernel_base);
    std::fprintf(stderr,
                 "LP3_ACTION_SUPERVISOR_STAGE stage=load-exit result=%d\n",
                 load_result);
    if (load_result != 0) {
        return 71;
    }
    if (!exact_shell_descriptor(
                executable_fd, kReSukiExecutableSize)) {
        std::fputs("LP3_ACTION_SUPERVISOR_ERROR stage=post-load-identity\n",
                   stderr);
        return 72;
    }
    char uid[16];
    char executable_path[64];
    int uid_length = std::snprintf(uid, sizeof(uid), "%d", manager_uid);
    int executable_path_length = std::snprintf(
            executable_path, sizeof(executable_path),
            "/proc/self/fd/%d", executable_fd);
    if (uid_length <= 0 || uid_length >= static_cast<int>(sizeof(uid)) ||
            executable_path_length <= 0 ||
            executable_path_length >=
                    static_cast<int>(sizeof(executable_path))) {
        return 73;
    }
    execl("/system/bin/linker64", "linker64", executable_path, "late-load",
          "--kmi", "android12-5.10",
          "--package-name", "com.resukisu.resukisu",
          "--foreground-manager-uid", uid,
          "--lp3-completion-path", argv[8],
          static_cast<char*>(nullptr));
    std::fprintf(stderr,
                 "LP3_ACTION_SUPERVISOR_ERROR stage=exec errno=%d\n", errno);
    return 74;
}

int action_daemon(int argc, char** argv) {
    int socket_fd = -1;
    if (argc != 3 ||
            !parse_decimal(argv[2], 0, 1'000'000, &socket_fd) ||
            !exact_root_process()) {
        return 75;
    }
    ActionDaemonReady ready;
    ready.pid = static_cast<std::int32_t>(syscall(SYS_getpid));
    ready.tid = static_cast<std::int32_t>(syscall(SYS_gettid));
    if (ready.pid <= 0 || ready.pid != ready.tid ||
            write(socket_fd, &ready, sizeof(ready)) !=
                    static_cast<ssize_t>(sizeof(ready))) {
        return 76;
    }

    ActionDaemonRequest request;
    char control[CMSG_SPACE(sizeof(int) * 3)] {};
    iovec vector {
        .iov_base = &request,
        .iov_len = sizeof(request),
    };
    msghdr message {};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    ssize_t received;
    do {
        received = recvmsg(socket_fd, &message, 0);
    } while (received < 0 && errno == EINTR);
    int descriptors[3] {-1, -1, -1};
    bool rights = false;
    if (received == static_cast<ssize_t>(sizeof(request)) &&
            !(message.msg_flags & (MSG_CTRUNC | MSG_TRUNC))) {
        cmsghdr* header = CMSG_FIRSTHDR(&message);
        rights = header != nullptr &&
                header->cmsg_level == SOL_SOCKET &&
                header->cmsg_type == SCM_RIGHTS &&
                header->cmsg_len == CMSG_LEN(sizeof(descriptors));
        if (rights) {
            std::memcpy(descriptors, CMSG_DATA(header), sizeof(descriptors));
            rights = CMSG_NXTHDR(&message, header) == nullptr;
        }
    }
    bool request_valid = rights &&
            request.magic == kActionDaemonRequestMagic &&
            (request.action == 1 || request.action == 2) &&
            request.manager_uid >= 10'000 &&
            request.manager_uid < 20'000 &&
            request.kernel_base >= kKernelLinkBase &&
            (request.kernel_base & (kKaslrAlignment - 1)) == 0 &&
            std::memchr(request.completion_path, '\0',
                        sizeof(request.completion_path)) != nullptr &&
            valid_completion_path(request.completion_path);
    if (!request_valid) {
        for (int descriptor : descriptors) {
            if (descriptor >= 0) {
                close(descriptor);
            }
        }
        return 77;
    }
    if (dup2(socket_fd, STDERR_FILENO) != STDERR_FILENO) {
        return 78;
    }
    char action_text[8];
    char uid_text[16];
    char loader_text[16];
    char module_text[16];
    char executable_text[16];
    char kernel_base_text[32];
    std::snprintf(action_text, sizeof(action_text), "%d", request.action);
    std::snprintf(uid_text, sizeof(uid_text), "%d", request.manager_uid);
    std::snprintf(loader_text, sizeof(loader_text), "%d", descriptors[0]);
    std::snprintf(module_text, sizeof(module_text), "%d", descriptors[1]);
    std::snprintf(
            executable_text, sizeof(executable_text), "%d", descriptors[2]);
    std::snprintf(kernel_base_text, sizeof(kernel_base_text),
                  "%" PRIx64, request.kernel_base);
    char name[] = "prism-action-supervisor";
    char mode[] = "action-supervisor";
    char* supervisor_arguments[] {
        name,
        mode,
        action_text,
        uid_text,
        loader_text,
        module_text,
        executable_text,
        kernel_base_text,
        request.completion_path,
        nullptr,
    };
    return action_supervisor(9, supervisor_arguments);
}

int clone_probe() {
    clone_args arguments {};
    arguments.exit_signal = SIGCHLD;
    std::uint64_t started = monotonic_nanoseconds();
    errno = 0;
    pid_t child = static_cast<pid_t>(syscall(
            SYS_clone3, &arguments, CLONE_ARGS_SIZE_VER0));
    int clone_error = child < 0 ? errno : 0;
    if (child == 0) {
        timespec delay {2, 0};
        (void)syscall(SYS_nanosleep, &delay, nullptr);
        _exit(42);
    }
    std::uint64_t returned = monotonic_nanoseconds();
    int status = 0;
    errno = 0;
    pid_t waited = child > 0 ? waitpid(child, &status, 0) : -1;
    int wait_error = waited < 0 ? errno : 0;
    std::printf(
            "{\"clone3_pid\":%d,\"clone3_errno\":%d,"
            "\"return_ns\":%" PRIu64 ",\"waited\":%d,"
            "\"wait_errno\":%d,\"status\":%d}\n",
            child, clone_error, returned - started, waited, wait_error, status);
    return child > 0 && clone_error == 0 && waited == child &&
            WIFEXITED(status) && WEXITSTATUS(status) == 42 &&
            returned - started < 500'000'000ULL ? 0 : 1;
}

struct SprayWorker {
    int pair[2] {-1, -1};
    pthread_t thread {};
    std::atomic<int> command {0};
    std::atomic<int> state {0};
    std::atomic<int> completed {0};
    std::uint8_t payload[128] {};
    bool created = false;
};

void wake_atomic(std::atomic<int>* value, int count) {
    syscall(SYS_futex, value, FUTEX_WAKE_PRIVATE, count,
            nullptr, nullptr, 0);
}

void* reusable_spray_worker(void* context) {
    auto* worker = static_cast<SprayWorker*>(context);
    int observed = 0;
    worker->state.store(1, std::memory_order_release);
    while (true) {
        int command = worker->command.load(std::memory_order_acquire);
        while (command == observed) {
            syscall(SYS_futex, &worker->command, FUTEX_WAIT_PRIVATE,
                    observed, nullptr, nullptr, 0);
            command = worker->command.load(std::memory_order_acquire);
        }
        if (command < 0) {
            break;
        }
        iovec vector {worker->payload, sizeof(worker->payload)};
        msghdr message {};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        worker->state.store(2, std::memory_order_release);
        int result;
        do {
            result = sendmsg(worker->pair[0], &message, MSG_NOSIGNAL);
        } while (result < 0 && errno == EINTR);
        worker->completed.store(
                result == static_cast<int>(sizeof(worker->payload))
                        ? command : -command,
                std::memory_order_release);
        observed = command;
        worker->state.store(1, std::memory_order_release);
    }
    worker->state.store(3, std::memory_order_release);
    return nullptr;
}

bool wait_workers(const std::vector<SprayWorker>& workers, int state,
                  std::uint64_t timeout_nanoseconds) {
    std::uint64_t deadline = monotonic_nanoseconds() + timeout_nanoseconds;
    while (monotonic_nanoseconds() < deadline) {
        int matching = 0;
        for (const auto& worker : workers) {
            matching += worker.state.load(std::memory_order_acquire) == state;
        }
        if (matching == static_cast<int>(workers.size())) {
            return true;
        }
        timespec delay {0, 100'000};
        syscall(SYS_nanosleep, &delay, nullptr);
    }
    return false;
}

int refill_worker(SprayWorker* worker) {
    iovec vector {worker->payload, sizeof(worker->payload)};
    msghdr message {};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    int messages = 0;
    while (sendmsg(worker->pair[0], &message,
                   MSG_DONTWAIT | MSG_NOSIGNAL) > 0) {
        ++messages;
    }
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? messages : -1;
}

bool drain_worker(SprayWorker* worker, int generation) {
    std::uint8_t payload[128];
    std::uint64_t deadline = monotonic_nanoseconds() + 2'000'000'000ULL;
    while (worker->completed.load(std::memory_order_acquire) != generation &&
           monotonic_nanoseconds() < deadline) {
        ssize_t received = recv(worker->pair[1], payload, sizeof(payload),
                                MSG_DONTWAIT);
        if (received == static_cast<ssize_t>(sizeof(payload)) ||
            (received < 0 && errno == EINTR)) {
            continue;
        }
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            timespec delay {0, 50'000};
            syscall(SYS_nanosleep, &delay, nullptr);
            continue;
        }
        return false;
    }
    if (worker->completed.load(std::memory_order_acquire) != generation) {
        return false;
    }
    ssize_t received;
    do {
        received = recv(worker->pair[1], payload, sizeof(payload),
                        MSG_DONTWAIT);
    } while (received > 0 || (received < 0 && errno == EINTR));
    return received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}

int spray_benchmark(int argc, char** argv) {
    int worker_count = 0;
    int iterations = 0;
    if (argc != 4 ||
        !parse_decimal(argv[2], 1, 2048, &worker_count) ||
        !parse_decimal(argv[3], 1, 100, &iterations)) {
        return 64;
    }
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(2, &affinity);
    if (sched_setaffinity(0, sizeof(affinity), &affinity) != 0) {
        return 65;
    }
    std::uint64_t setup_started = monotonic_nanoseconds();
    std::vector<SprayWorker> workers(static_cast<std::size_t>(worker_count));
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setstacksize(&attributes, 32 * 1024);
    bool setup = true;
    for (int index = 0; setup && index < worker_count; ++index) {
        SprayWorker& worker = workers[static_cast<std::size_t>(index)];
        std::memset(worker.payload, index & 0xff, sizeof(worker.payload));
        int send_buffer = 4096;
        setup = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
                           0, worker.pair) == 0 &&
                setsockopt(worker.pair[0], SOL_SOCKET, SO_SNDBUF,
                           &send_buffer, sizeof(send_buffer)) == 0 &&
                pthread_create(&worker.thread, &attributes,
                               reusable_spray_worker, &worker) == 0;
        worker.created = setup;
    }
    pthread_attr_destroy(&attributes);
    setup = setup && wait_workers(workers, 1, 5'000'000'000ULL);
    std::uint64_t setup_duration = monotonic_nanoseconds() - setup_started;
    bool pass = setup;
    for (int iteration = 1; pass && iteration <= iterations; ++iteration) {
        std::uint64_t refill_started = monotonic_nanoseconds();
        int prefilled = 0;
        for (auto& worker : workers) {
            int messages = refill_worker(&worker);
            if (messages <= 0) {
                pass = false;
                break;
            }
            prefilled += messages;
        }
        std::uint64_t refill_duration =
                monotonic_nanoseconds() - refill_started;
        std::uint64_t activate_started = monotonic_nanoseconds();
        for (auto& worker : workers) {
            worker.command.store(iteration, std::memory_order_release);
            wake_atomic(&worker.command, 1);
        }
        pass = pass && wait_workers(workers, 2, 2'000'000'000ULL);
        timespec dwell {0, 20'000'000};
        syscall(SYS_nanosleep, &dwell, nullptr);
        int blocked = 0;
        for (const auto& worker : workers) {
            blocked += worker.state.load(std::memory_order_acquire) == 2 &&
                    worker.completed.load(std::memory_order_acquire) !=
                            iteration;
        }
        pass = pass && blocked == worker_count;
        std::uint64_t activate_duration =
                monotonic_nanoseconds() - activate_started;
        std::uint64_t release_started = monotonic_nanoseconds();
        for (auto& worker : workers) {
            pass = drain_worker(&worker, iteration) && pass;
        }
        pass = pass && wait_workers(workers, 1, 2'000'000'000ULL);
        std::uint64_t release_duration =
                monotonic_nanoseconds() - release_started;
        std::printf(
                "{\"iteration\":%d,\"workers\":%d,"
                "\"prefilled\":%d,\"blocked\":%d,"
                "\"refill_ns\":%" PRIu64 ","
                "\"activate_ns\":%" PRIu64 ","
                "\"release_ns\":%" PRIu64 ",\"pass\":%s}\n",
                iteration, worker_count, prefilled, blocked,
                refill_duration, activate_duration, release_duration,
                pass ? "true" : "false");
        std::fflush(stdout);
    }
    for (auto& worker : workers) {
        if (worker.created) {
            worker.command.store(-1, std::memory_order_release);
            wake_atomic(&worker.command, 1);
            pthread_join(worker.thread, nullptr);
        }
        for (int& descriptor : worker.pair) {
            if (descriptor >= 0) {
                close(descriptor);
                descriptor = -1;
            }
        }
    }
    std::printf(
            "{\"stage\":\"spray-benchmark\",\"setup_ns\":%" PRIu64
            ",\"workers\":%d,\"iterations\":%d,\"pass\":%s}\n",
            setup_duration, worker_count, iterations,
            pass ? "true" : "false");
    return pass ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && std::strcmp(argv[1], "action-daemon") == 0) {
        return action_daemon(argc, argv);
    }
    if (argc >= 2 && std::strcmp(argv[1], "action-supervisor") == 0) {
        return action_supervisor(argc, argv);
    }
    if (argc >= 2 && std::strcmp(argv[1], "spray-benchmark") == 0) {
        return spray_benchmark(argc, argv);
    }
    if (argc == 4 && std::strcmp(argv[1], "route-probe") == 0) {
        prism::primitive::Result result = prism::primitive::probe_route(
                argv[2], argv[3], event, nullptr);
        return result.passed ? 0 : 1;
    }
    if (argc != 2) {
        std::fputs(
                "usage: prism-primitive"
                " probe|broker-probe|clone-probe|route-probe"
                " <service-template> <start-template>|spray-benchmark"
                "|action-supervisor ...\n",
                stderr);
        return 64;
    }
    prism::primitive::Result result;
    if (std::strcmp(argv[1], "probe") == 0) {
        prism::primitive::Configuration configuration;
        result = prism::primitive::probe(configuration, event, nullptr);
    } else if (std::strcmp(argv[1], "broker-probe") == 0) {
        result = prism::primitive::probe_broker(event, nullptr);
    } else if (std::strcmp(argv[1], "clone-probe") == 0) {
        return clone_probe();
    } else {
        std::fputs(
                "usage: prism-primitive"
                " probe|broker-probe|clone-probe|route-probe"
                " <service-template> <start-template>|spray-benchmark"
                "|action-supervisor ...\n",
                stderr);
        return 64;
    }
    return result.passed ? 0 : 1;
}
