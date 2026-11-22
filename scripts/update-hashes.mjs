import fs from "node:fs/promises";
import crypto from "node:crypto";
import { Readable } from "node:stream";

const MANIFEST_PATH = "./manifest.json";

const ALLOWED_HOSTS = [
  "windows.php.net",
  "nodejs.org",
  "nginx.org",
  "www.apachelounge.com",
  "dev.mysql.com",
  "get.enterprisedb.com",
  "github.com",
  "objects.githubusercontent.com",
  "pub-2d96730c227e4b95b37c19eac13b91e0.r2.dev",
  "symen.mulyaranadhan.workers.dev",
];

function validateUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "https:") {
    throw new Error(`Protokol wajib HTTPS: ${rawUrl}`);
  }
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    throw new Error(`Domain tidak ada di whitelist: ${parsed.hostname}`);
  }
}

async function computeSha256FromUrl(url) {
  validateUrl(url);

  const res = await fetch(url, {
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      Referer: "https://www.apachelounge.com/download/",
    },
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status} (${res.statusText}) untuk ${url}`);
  }

  if (!res.body) {
    throw new Error(`Response body kosong untuk ${url}`);
  }

  const hash = crypto.createHash("sha256");
  const stream = Readable.fromWeb(res.body);

  let headerBuffer = Buffer.alloc(0);
  let headerVerified = false;
  let totalBytes = 0;

  for await (const chunk of stream) {
    const buf = Buffer.from(chunk);
    totalBytes += buf.length;

    // Kumpulkan minimal 4 byte pertama untuk mengecek magic bytes file ZIP (PK\x03\x04)
    if (!headerVerified) {
      headerBuffer = Buffer.concat([headerBuffer, buf]);
      if (headerBuffer.length >= 4) {
        const isZip =
          headerBuffer[0] === 0x50 &&
          headerBuffer[1] === 0x4b &&
          headerBuffer[2] === 0x03 &&
          headerBuffer[3] === 0x04;

        if (!isZip) {
          const preview = headerBuffer
            .subarray(0, 120)
            .toString("utf8")
            .replace(/\s+/g, " ");
          throw new Error(
            `File bukan archive ZIP valid (kemungkinan halaman HTML/Soft 404). Preview: "${preview}"`,
          );
        }
        headerVerified = true;
      }
    }

    hash.update(buf);
  }

  if (!headerVerified || totalBytes < 1024) {
    throw new Error(
      `Ukuran file terlalu kecil atau tidak valid (${totalBytes} bytes) untuk ${url}`,
    );
  }

  return {
    sha256: hash.digest("hex"),
    sizeBytes: totalBytes,
  };
}

async function main() {
  const raw = await fs.readFile(MANIFEST_PATH, "utf8");
  const manifest = JSON.parse(raw);

  let updatedCount = 0;
  let hasError = false;

  for (const [serviceName, items] of Object.entries(manifest.services)) {
    for (const item of items) {
      if (!item.sha256 || item.sha256 === "REPLACE_WITH_ACTUAL_SHA256") {
        console.log(`[${serviceName}] Menghitung SHA256 untuk ${item.id}...`);
        try {
          const { sha256, sizeBytes } = await computeSha256FromUrl(item.url);
          item.sha256 = sha256;
          updatedCount++;
          const sizeMb = (sizeBytes / (1024 * 1024)).toFixed(2);
          console.log(`  -> OK (${sizeMb} MB): ${sha256}`);
        } catch (err) {
          hasError = true;
          console.error(`  -> GAGAL (${item.id}): ${err.message}`);
        }
      }
    }
  }

  if (updatedCount > 0) {
    manifest.updated_at = new Date().toISOString().split("T")[0];
    await fs.writeFile(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + "\n");
    console.log(
      `\nSelesai! ${updatedCount} entry di manifest.json berhasil diperbarui.`,
    );
  } else {
    console.log("\nTidak ada perubahan yang ditulis ke manifest.json.");
  }

  if (hasError) {
    console.error(
      "\nTerdapat URL yang gagal diverifikasi. Cek log error di atas.",
    );
    process.exitCode = 1;
  }
}

main();
