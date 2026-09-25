# Unlocking the Light Phone III bootloader

Successfully demonstrated on a **Light Phone III (TLP301), firmware `00WW_1_440000`**. This is the manual method we used; it is not yet an unlock feature in Prism. **Unlocking factory-resets the phone.**

## Why ordinary unlocking fails

Enabling OEM unlocking is not enough on this firmware. The bootloader also requires a separate FIH authorisation, otherwise `fastboot flashing unlock` returns “Flashing Unlock is not allowed”.

We found that its cached-authorisation mechanism accepts a self-signed certificate. It checks the signature against the key inside the supplied certificate, without checking that the certificate belongs to Light. Prism's temporary root lets us place a valid, device-specific record where the bootloader reads it.

## The method

1. **Back up your data.** Copy photos, videos and anything else you need off the phone. Verify the copies before continuing.

2. **Activate root with Prism.** Start Shizuku, run Prism, and allow the ADB Shell superuser access in ReSukiSU.

3. **Prepare a one-use authorisation record.** Back up the complete `mfd` partition and read the phone's hardware ID. Generate a self-signed RSA-2048 certificate and sign the SHA-256 digest of that ID, formatted as eight uppercase hexadecimal characters. Package the certificate and signature into the bootloader's record format, with authorisation mode `1` and a boot count of `1`. The record must be generated for that phone.

4. **Enable OEM unlocking and stage the record.** On our phone, the `no_factory_reset` user restriction first needed clearing. Enable OEM unlocking through Android's OEM-lock service and confirm its stored FRP bit is `1`. Write only the existing 4 KiB certificate area at offset `0x3000` in `mfd`. Read back the partition and verify that everything outside that area is unchanged.

5. **Reboot directly into the bootloader and unlock.** The authorisation is consumed on the next boot, so do not boot Android in between:

   ```sh
   adb reboot bootloader
   fastboot flashing get_unlock_ability
   fastboot oem getpermissions
   ```

   These should report `1` and `permissions=flash`. Then run:

   ```sh
   fastboot flashing unlock
   ```

   Select **UNLOCK THE BOOTLOADER** on the phone and confirm using its controls. Wait for the reset; avoid sending further fastboot commands while the confirmation screen is open.

6. **Verify after setup.** Re-enable USB debugging and run:

   ```sh
   adb shell getprop ro.boot.flash.locked
   adb shell getprop ro.boot.vbmeta.device_state
   adb shell getprop ro.boot.verifiedbootstate
   ```

   The expected results are **`0`**, **`unlocked`**, and **`orange`**.

The signed bootloader and stock ROM remain unchanged. Magisk or a custom ROM would be a separate installation afterwards.

The record-generation and staging steps currently require the device-specific research tooling; this is not a complete copy-and-paste installer. See the [technical writeup and evidence](research/light-phone-iii-local-authorisation.md) for the analysed behaviour and verification limits.
