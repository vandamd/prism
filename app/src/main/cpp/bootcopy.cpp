#include <jni.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdint>
#include <fcntl.h>
#include <linux/capability.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string>
#include <vector>

namespace {

int output_fd = -1;
int status_fd = -1;
std::uint8_t* output_map = nullptr;
std::uint8_t* status_map = nullptr;
std::size_t output_size = 0;

void close_output() {
    if (output_map != nullptr) {
        munmap(output_map, output_size);
        output_map = nullptr;
    }
    if (status_map != nullptr) {
        munmap(status_map, 1);
        status_map = nullptr;
    }
    if (output_fd >= 0) {
        close(output_fd);
        output_fd = -1;
    }
    if (status_fd >= 0) {
        close(status_fd);
        status_fd = -1;
    }
    output_size = 0;
}

}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_BootCopy_prepareDestination(
        JNIEnv* environment, jclass, jstring destination_value,
        jlong expected_size) {
    const char* destination = environment->GetStringUTFChars(
            destination_value, nullptr);
    if (destination == nullptr) {
        return environment->NewStringUTF(
                "BOOT_COPY status=fail reason=path");
    }
    close_output();
    output_fd = open(destination,
            O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    output_size = static_cast<std::size_t>(expected_size);
    bool ready = output_fd >= 0 && expected_size > 0 &&
            ftruncate(output_fd, expected_size) == 0;
    if (ready) {
        void* mapping = mmap(nullptr, output_size,
                PROT_READ | PROT_WRITE, MAP_SHARED, output_fd, 0);
        ready = mapping != MAP_FAILED;
        if (ready) {
            output_map = static_cast<std::uint8_t*>(mapping);
        }
    }
    std::string status_path(destination);
    status_path += ".status";
    if (ready) {
        status_fd = open(status_path.c_str(),
                O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        ready = status_fd >= 0 && ftruncate(status_fd, 1) == 0;
    }
    if (ready) {
        void* mapping = mmap(nullptr, 1, PROT_READ | PROT_WRITE,
                MAP_SHARED, status_fd, 0);
        ready = mapping != MAP_FAILED;
        if (ready) {
            status_map = static_cast<std::uint8_t*>(mapping);
            status_map[0] = 0;
        }
    }
    int saved_errno = ready ? 0 : errno;
    environment->ReleaseStringUTFChars(destination_value, destination);
    if (!ready) {
        close_output();
    }
    char state[128];
    std::snprintf(state, sizeof(state),
            "BOOT_COPY status=%s stage=destination errno=%d",
            ready ? "ready" : "fail", saved_errno);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_BootCopy_whenReadable(
        JNIEnv* environment, jclass, jstring source_value,
        jint timeout_millis) {
    const char* source = environment->GetStringUTFChars(source_value, nullptr);
    if (source == nullptr || output_map == nullptr || status_map == nullptr) {
        if (source != nullptr) {
            environment->ReleaseStringUTFChars(source_value, source);
        }
        return environment->NewStringUTF(
                "BOOT_COPY status=fail reason=not-prepared");
    }

    int input = -1;
    int open_error = 0;
    auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(timeout_millis);
    while (std::chrono::steady_clock::now() < deadline) {
        input = open(source, O_RDONLY | O_CLOEXEC);
        if (input >= 0) {
            break;
        }
        open_error = errno;
        usleep(5000);
    }

    environment->ReleaseStringUTFChars(source_value, source);

    std::uint64_t total = 0;
    int copy_error = 0;
    while (input >= 0 && copy_error == 0 && total < output_size) {
        std::size_t remaining = output_size - total;
        std::size_t request = std::min<std::size_t>(remaining, 1024 * 1024);
        ssize_t count = read(input, output_map + total, request);
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            copy_error = errno;
            break;
        }
        total += static_cast<std::uint64_t>(count);
    }
    if (input >= 0) {
        close(input);
    }
    if (copy_error == 0 && total != output_size) {
        copy_error = EIO;
    }
    if (copy_error == 0) {
        if (msync(output_map, output_size, MS_SYNC) != 0) {
            copy_error = errno;
        } else {
            status_map[0] = 1;
            msync(status_map, 1, MS_SYNC);
        }
    }

    char state[192];
    if (input < 0) {
        std::snprintf(state, sizeof(state),
                "BOOT_COPY status=miss reason=open errno=%d", open_error);
    } else {
        std::snprintf(state, sizeof(state),
                "BOOT_COPY status=%s size=%" PRIu64 " errno=%d",
                copy_error == 0 ? "pass" : "fail", total, copy_error);
    }
    close_output();
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT void JNICALL
Java_com_vandam_prism_BootCopy_closeDestination(JNIEnv*, jclass) {
    close_output();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vandam_prism_BootCopy_waitForArmLock(
        JNIEnv* environment, jclass, jstring path_value) {
    const char* path = environment->GetStringUTFChars(path_value, nullptr);
    if (path == nullptr) {
        return JNI_FALSE;
    }
    int descriptor = open(path, O_RDWR | O_CLOEXEC);
    bool locked = false;
    while (descriptor >= 0 && !locked) {
        if (flock(descriptor, LOCK_EX) == 0) {
            locked = true;
        } else if (errno != EINTR) {
            break;
        }
    }
    if (locked) {
        flock(descriptor, LOCK_UN);
    }
    if (descriptor >= 0) {
        close(descriptor);
    }
    environment->ReleaseStringUTFChars(path_value, path);
    return locked ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_vandam_prism_BootCopy_rebootDevice(JNIEnv*, jclass) {
    if (reboot(RB_AUTOBOOT) == 0) {
        return 0;
    }
    return -errno;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_BootCopy_rootWatchdogIdentity(
        JNIEnv* environment, jclass) {
    uid_t real_uid = static_cast<uid_t>(-1);
    uid_t effective_uid = static_cast<uid_t>(-1);
    uid_t saved_uid = static_cast<uid_t>(-1);
    gid_t real_gid = static_cast<gid_t>(-1);
    gid_t effective_gid = static_cast<gid_t>(-1);
    gid_t saved_gid = static_cast<gid_t>(-1);
    int uid_result = getresuid(&real_uid, &effective_uid, &saved_uid);
    int gid_result = getresgid(&real_gid, &effective_gid, &saved_gid);
    uid_t filesystem_uid = static_cast<uid_t>(
            syscall(SYS_setfsuid, static_cast<uid_t>(-1)));
    gid_t filesystem_gid = static_cast<gid_t>(
            syscall(SYS_setfsgid, static_cast<gid_t>(-1)));
    __user_cap_header_struct header {};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    __user_cap_data_struct data[2] {};
    int cap_result = static_cast<int>(syscall(SYS_capget, &header, data));
    std::uint64_t effective_caps =
            static_cast<std::uint64_t>(data[0].effective) |
            (static_cast<std::uint64_t>(data[1].effective) << 32U);
    bool pass = uid_result == 0 && gid_result == 0 && cap_result == 0 &&
            real_uid == 0 && effective_uid == 0 && saved_uid == 0 &&
            filesystem_uid == 0 && real_gid == 0 && effective_gid == 0 &&
            saved_gid == 0 && filesystem_gid == 0 &&
            (effective_caps & (UINT64_C(1) << 22U)) != 0;
    char state[256];
    std::snprintf(state, sizeof(state),
            "status=%s uid=%u,%u,%u,%u gid=%u,%u,%u,%u"
            " cap_eff=%016" PRIx64 " uid_rc=%d gid_rc=%d cap_rc=%d",
            pass ? "pass" : "fail",
            real_uid, effective_uid, saved_uid, filesystem_uid,
            real_gid, effective_gid, saved_gid, filesystem_gid,
            effective_caps, uid_result, gid_result, cap_result);
    return environment->NewStringUTF(state);
}
