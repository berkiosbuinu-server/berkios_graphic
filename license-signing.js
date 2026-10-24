import { sign, verify, createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";

export function loadLicenseKeys(env = process.env) {
  const privatePath = env.BERKIOS_LICENSE_PRIVATE_KEY_FILE;
  const publicPath = env.BERKIOS_LICENSE_PUBLIC_KEY_FILE;
  if (!privatePath || !publicPath) return null;
  try {
    return { privateKey: createPrivateKey(readFileSync(privatePath, "utf8")), publicKey: createPublicKey(readFileSync(publicPath, "utf8")) };
  } catch (error) {
    throw new Error(`Clés de licence illisibles: ${error.message}`);
  }
}
export function signLease(payload, privateKey) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign(null, Buffer.from(encoded), privateKey).toString("base64url");
  return { algorithm: "Ed25519", payload: encoded, signature };
}
export function verifyLease(envelope, publicKey, { machineId, now = Date.now() } = {}) {
  if (!envelope || envelope.algorithm !== "Ed25519" || typeof envelope.payload !== "string" || typeof envelope.signature !== "string") return { ok: false, reason: "format_invalid" };
  let valid = false;
  try { valid = verify(null, Buffer.from(envelope.payload), publicKey, Buffer.from(envelope.signature, "base64url")); } catch { valid = false; }
  if (!valid) return { ok: false, reason: "signature_invalid" };
  let payload;
  try { payload = JSON.parse(Buffer.from(envelope.payload, "base64url").toString("utf8")); } catch { return { ok: false, reason: "payload_invalid" }; }
  if (!payload || !payload.machineId || (machineId && payload.machineId !== machineId)) return { ok: false, reason: "machine_mismatch" };
  if (!Number.isFinite(payload.expiresAt) || now >= payload.expiresAt) return { ok: false, reason: "lease_expired" };
  if (!Number.isFinite(payload.issuedAt) || payload.issuedAt > now + 300000) return { ok: false, reason: "issued_in_future" };
  return { ok: true, payload };
}
