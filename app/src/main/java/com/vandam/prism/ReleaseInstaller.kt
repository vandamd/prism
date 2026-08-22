package com.vandam.prism

import android.content.Context
import android.content.pm.PackageManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

enum class ReleasePackage {
    Shizuku,
    ReSukiSU,
}

object ReleaseInstaller {
    private const val SHIZUKU_RELEASE_URL =
        "https://api.github.com/repos/RikkaApps/Shizuku/releases/latest"
    private const val RESUKISU_RELEASES_URL =
        "https://api.github.com/repos/ReSukiSU/ReSukiSU/releases?per_page=10"
    private const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
    private const val RESUKISU_PACKAGE = "com.resukisu.resukisu"
    private const val SHIZUKU_CERTIFICATE =
        "268b5590e868fb08bae7e0ac413564cd1ff88f5ccff74af9dbd0dc918e30db30"
    private const val RESUKISU_CERTIFICATE =
        "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64"
    private const val MAX_APK_BYTES = 64L * 1024L * 1024L

    fun download(
        context: Context,
        target: ReleasePackage,
    ): File {
        val directory = File(context.cacheDir, "downloads").apply { mkdirs() }
        val fileName = target.name.lowercase()
        val temporary = File(directory, "$fileName.apk.part")
        val apk = File(directory, "$fileName.apk")
        temporary.delete()
        apk.delete()
        try {
            val release = release(target)
            download(release, temporary)
            verifyDigest(temporary, release.digest)
            verifyPackage(context.packageManager, temporary, target)
            require(temporary.renameTo(apk)) { "Could not prepare the APK" }
            return apk
        } catch (failure: Throwable) {
            temporary.delete()
            apk.delete()
            throw failure
        }
    }

    fun delete(apk: File?) {
        apk?.let {
            it.delete()
            it.parentFile?.delete()
        }
    }

    private fun release(target: ReleasePackage): ReleaseAsset =
        when (target) {
            ReleasePackage.Shizuku -> shizukuRelease()
            ReleasePackage.ReSukiSU -> reSukiSURelease()
        }

    private fun shizukuRelease(): ReleaseAsset {
        val release = JSONObject(request(SHIZUKU_RELEASE_URL))
        return selectAsset(release) { name ->
            name.startsWith("shizuku-") && name.endsWith("-release.apk")
        }
    }

    private fun reSukiSURelease(): ReleaseAsset {
        val releases = JSONArray(request(RESUKISU_RELEASES_URL))
        val release =
            (0 until releases.length())
                .map(releases::getJSONObject)
                .filterNot { it.getBoolean("draft") }
                .maxByOrNull { it.getString("published_at") }
                ?: error("ReSukiSU does not have a published release")
        return selectAsset(release) { name ->
            name.startsWith("ReSukiSU_") && name.endsWith("-arm64-v8a-release.apk")
        }
    }

    private fun selectAsset(
        release: JSONObject,
        acceptsName: (String) -> Boolean,
    ): ReleaseAsset {
        val assets = release.getJSONArray("assets")
        val asset =
            (0 until assets.length())
                .map(assets::getJSONObject)
                .singleOrNull {
                    acceptsName(it.getString("name")) &&
                        it.getString("content_type") == "application/vnd.android.package-archive"
                } ?: error("The release does not contain one compatible APK")
        val size = asset.getLong("size")
        require(size in 1..MAX_APK_BYTES) { "The APK size is invalid" }
        val url = URL(asset.getString("browser_download_url"))
        require(url.protocol == "https" && url.host == "github.com")
        require(url.path.contains("/releases/download/"))
        return ReleaseAsset(
            url = url,
            size = size,
            digest = asset.optString("digest").takeIf { it.startsWith("sha256:") }?.removePrefix("sha256:"),
        )
    }

    private fun request(url: String): String {
        val connection = open(URL(url))
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        connection.setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
        connection.setRequestProperty("User-Agent", "Prism/${BuildConfig.VERSION_NAME}")
        return connection.use {
            requireSuccessful(it)
            it.inputStream.bufferedReader().use { reader -> reader.readText() }
        }
    }

    private fun download(
        release: ReleaseAsset,
        destination: File,
    ) {
        val connection = open(release.url)
        connection.use {
            requireSuccessful(it)
            var written = 0L
            it.inputStream.use { input ->
                destination.outputStream().buffered().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        written += count
                        require(written <= release.size && written <= MAX_APK_BYTES) {
                            "The APK is larger than advertised"
                        }
                        output.write(buffer, 0, count)
                    }
                }
            }
            require(written == release.size) { "The APK download is incomplete" }
        }
    }

    private fun verifyDigest(
        apk: File,
        expected: String?,
    ) {
        if (expected == null) return
        val digest = MessageDigest.getInstance("SHA-256")
        apk.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        require(digest.digest().toHex() == expected) { "The APK digest is invalid" }
    }

    private fun verifyPackage(
        packageManager: PackageManager,
        apk: File,
        target: ReleasePackage,
    ) {
        val info =
            packageManager.getPackageArchiveInfo(
                apk.absolutePath,
                PackageManager.GET_SIGNING_CERTIFICATES,
            ) ?: error("The download is not a valid APK")
        val expectedPackage =
            when (target) {
                ReleasePackage.Shizuku -> SHIZUKU_PACKAGE
                ReleasePackage.ReSukiSU -> RESUKISU_PACKAGE
            }
        val expectedCertificate =
            when (target) {
                ReleasePackage.Shizuku -> SHIZUKU_CERTIFICATE
                ReleasePackage.ReSukiSU -> RESUKISU_CERTIFICATE
            }
        require(info.packageName == expectedPackage) { "The APK has an unexpected package name" }
        val certificates = info.signingInfo?.apkContentsSigners.orEmpty()
        require(certificates.size == 1) { "The APK has an unexpected signature" }
        val digest =
            MessageDigest.getInstance("SHA-256")
                .digest(certificates.single().toByteArray())
                .toHex()
        require(digest == expectedCertificate) { "The APK signature is invalid" }
    }

    private fun open(url: URL): HttpURLConnection =
        (url.openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 30_000
            instanceFollowRedirects = true
        }

    private fun requireSuccessful(connection: HttpURLConnection) {
        require(connection.responseCode == HttpURLConnection.HTTP_OK) {
            "GitHub returned HTTP ${connection.responseCode}"
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private inline fun <T> HttpURLConnection.use(block: (HttpURLConnection) -> T): T =
        try {
            block(this)
        } finally {
            disconnect()
        }

    private data class ReleaseAsset(
        val url: URL,
        val size: Long,
        val digest: String?,
    )
}
