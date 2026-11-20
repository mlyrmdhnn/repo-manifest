import fs from "node:fs/promises";
import crypto from "node:crypto";
import { Readable } from "node:stream";

const MANIFEST_PATH = "./manifest.json";

async function computeSha256FromUrl(url) {
  const res = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} untuk ${url}`);

  const hash = crypto.createHash("sha256");
  const stream = Readable.fromWeb(res.body);

  for await (const chunk of stream) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

async function main() {
  const raw = await fs.readFile(MANIFEST_PATH, "utf8");
  const manifest = JSON.parse(raw);
  let updated = false;

  for (const [serviceName, items] of Object.entries(manifest.services)) {
    for (const item of items) {
      // Hanya hitung kalau belum ada sha256 atau masih placeholder
      if (!item.sha256 || item.sha256 === "REPLACE_WITH_ACTUAL_SHA256") {
        console.log(`Menghitung SHA256: ${item.id} (${item.url})...`);
        try {
          item.sha256 = await computeSha256FromUrl(item.url);
          updated = true;
          console.log(`  -> OK: ${item.sha256}`);
        } catch (err) {
          console.error(`  -> GAGAL (${item.id}): ${err.message}`);
        }
      }
    }
  }

  if (updated) {
    manifest.updated_at = new Date().toISOString().split("T")[0];
    await fs.writeFile(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + "\n");
    console.log("manifest.json berhasil diperbarui!");
  } else {
    console.log("Semua SHA256 sudah lengkap, tidak ada perubahan.");
  }
}

main();
