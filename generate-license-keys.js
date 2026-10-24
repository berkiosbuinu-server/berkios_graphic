import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
const privatePath = resolve(process.env.BERKIOS_LICENSE_PRIVATE_KEY_FILE || "./secrets/license-ed25519-private.pem");
const publicPath = resolve(process.env.BERKIOS_LICENSE_PUBLIC_KEY_FILE || "./secrets/license-ed25519-public.pem");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
for (const p of [privatePath, publicPath]) mkdirSync(dirname(p), { recursive: true });
writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
writeFileSync(publicPath, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o644 });
console.log(`Clé privée créée: ${privatePath}
Clé publique créée: ${publicPath}
IMPORTANT: conservez la clé privée uniquement sur le VPS et sauvegardez-la en lieu sûr.`);
