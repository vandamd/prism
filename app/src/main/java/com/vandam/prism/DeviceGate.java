package com.vandam.prism;

import android.content.Context;
import android.os.Build;
import android.system.Os;
import android.system.OsConstants;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class DeviceGate {
    private static final String PROFILE_FILE = "device_profiles.json";

    private DeviceGate() {}

    public static String verify(Context context) {
        List<String> mismatches = new ArrayList<>();
        try {
            JSONObject profile = loadProfile(context);
            JSONObject product = profile.getJSONObject("product");
            JSONObject system = profile.getJSONObject("system");
            JSONObject kernel = profile.getJSONObject("kernel");
            JSONObject boot = profile.getJSONObject("required_boot_state");

            match(mismatches, "device", Build.DEVICE,
                    product.getString("device"));
            match(mismatches, "model", Build.MODEL,
                    product.getString("model"));
            match(mismatches, "manufacturer", Build.MANUFACTURER,
                    product.getString("manufacturer"));
            match(mismatches, "board", Build.BOARD,
                    product.getString("board"));
            match(mismatches, "platform", property("ro.board.platform"),
                    product.getString("platform"));
            match(mismatches, "hardware", Build.HARDWARE,
                    product.getString("hardware"));
            match(mismatches, "soc", property("ro.soc.model"),
                    product.getString("soc_model"));
            match(mismatches, "soc_manufacturer",
                    property("ro.soc.manufacturer"),
                    product.getString("soc_manufacturer"));

            match(mismatches, "display", Build.DISPLAY,
                    system.getString("display_id"));
            match(mismatches, "build_id", Build.ID,
                    system.getString("build_id"));
            match(mismatches, "incremental", Build.VERSION.INCREMENTAL,
                    system.getString("incremental"));
            match(mismatches, "release", Build.VERSION.RELEASE,
                    system.getString("release"));
            match(mismatches, "sdk", Integer.toString(Build.VERSION.SDK_INT),
                    Integer.toString(system.getInt("sdk")));
            match(mismatches, "patch", Build.VERSION.SECURITY_PATCH,
                    system.getString("security_patch"));
            match(mismatches, "fingerprint", Build.FINGERPRINT,
                    system.getString("fingerprint"));

            match(mismatches, "kernel", Os.uname().release,
                    kernel.getString("release"));
            match(mismatches, "page_size",
                    Long.toString(Os.sysconf(OsConstants._SC_PAGESIZE)),
                    Integer.toString(kernel.getInt("page_size")));

            match(mismatches, "verified_boot",
                    property("ro.boot.verifiedbootstate"),
                    boot.getString("verified_boot"));
            match(mismatches, "flash_locked",
                    property("ro.boot.flash.locked"),
                    boot.getBoolean("flash_locked") ? "1" : "0");
            match(mismatches, "vbmeta_state",
                    property("ro.boot.vbmeta.device_state"), "locked");
            matchIfVisible(mismatches, "virtual_ab",
                    property("ro.virtual_ab.enabled"),
                    Boolean.toString(boot.getBoolean("virtual_ab")));
            match(mismatches, "dynamic_partitions",
                    property("ro.boot.dynamic_partitions"),
                    Boolean.toString(boot.getBoolean("dynamic_partitions")));

            if (mismatches.isEmpty()) {
                return "status=pass stage=device-gate profile=" +
                        profile.getString("id");
            }
            return "status=fail stage=device-gate mismatch=" +
                    String.join(",", mismatches);
        } catch (Exception exception) {
            return "status=fail stage=device-gate reason=" +
                    exception.getClass().getSimpleName();
        }
    }

    private static JSONObject loadProfile(Context context) throws Exception {
        try (InputStream input = context.getAssets().open(PROFILE_FILE);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                output.write(buffer, 0, count);
            }
            JSONObject root = new JSONObject(
                    output.toString(StandardCharsets.UTF_8.name()));
            return root.getJSONArray("profiles").getJSONObject(0);
        }
    }

    private static String property(String name) throws Exception {
        Process process = new ProcessBuilder("/system/bin/getprop", name)
                .redirectErrorStream(true)
                .start();
        String value;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(),
                        StandardCharsets.UTF_8))) {
            value = reader.readLine();
        }
        if (process.waitFor() != 0) {
            throw new IllegalStateException("getprop");
        }
        return value == null ? "" : value.trim();
    }

    private static void match(List<String> mismatches, String name,
                              String actual, String expected) {
        if (!expected.equals(actual)) {
            mismatches.add(name);
        }
    }

    private static void matchIfVisible(List<String> mismatches, String name,
                                       String actual, String expected) {
        if (!actual.isEmpty()) {
            match(mismatches, name, actual, expected);
        }
    }
}
