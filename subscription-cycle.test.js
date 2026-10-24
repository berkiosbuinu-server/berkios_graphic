import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:net";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const backendDir = dirname(fileURLToPath(import.meta.url));
async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

test("cycle d'abonnement : renouvellement conserve la machine, transfert autorisé, révocation vers Free", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "berkios-subscription-cycle-"));
  const port = await freePort();
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePath = join(dir, "private.pem"), publicPath = join(dir, "public.pem");
  writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }));
  writeFileSync(publicPath, publicKey.export({ type: "spki", format: "pem" }));
  const adminToken = "test-admin-token-only";
  const child = spawn(process.execPath, ["--experimental-sqlite", "server.js"], {
    cwd: backendDir,
    env: { ...process.env, HOST: "127.0.0.1", PORT: String(port), BERKIOS_DB: join(dir, "test.sqlite"), BERKIOS_SUPER_ADMIN_TOKEN: adminToken, BERKIOS_LICENSE_PRIVATE_KEY_FILE: privatePath, BERKIOS_LICENSE_PUBLIC_KEY_FILE: publicPath },
    stdio: "ignore"
  });
  t.after(async () => { child.kill("SIGTERM"); await new Promise((resolve) => setTimeout(resolve, 150)); rmSync(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${port}`;
  const post = async (route, body, headers = {}) => {
    const response = await fetch(`${base}${route}`, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() };
  };
  let started = false;
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(`${base}/api/health`)).ok) { started = true; break; } } catch { /* serveur en démarrage */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(started, true, "le backend démarre");
  const registered = await post("/api/auth/register", { email: "cycle@example.com", phone: "+243812345678", password: "a-very-secure-password" });
  assert.equal(registered.status, 200);
  const auth = { Authorization: `Bearer ${registered.data.token}` };
  const admin = { "X-Berkios-Admin-Token": adminToken };
  assert.equal((await fetch(`${base}/api/admin/users`)).status, 403, "la liste des comptes exige le jeton administrateur");
  assert.equal((await fetch(`${base}/admin`)).status, 200, "le tableau de bord est servi par le backend");
  const listed = await fetch(`${base}/api/admin/users?q=cycle%40example.com`, { headers: admin });
  assert.equal(listed.status, 200);
  assert.equal((await listed.json()).users[0].email, "cycle@example.com");
  assert.equal((await fetch(`${base}/api/admin/audit`, { headers: admin })).status, 200);
  const providers = await fetch(`${base}/api/payments/providers`);
  assert.equal(providers.status, 200);
  assert.equal((await providers.json()).onlinePaymentsEnabled, false, "les paiements en ligne ne sont pas annoncés comme actifs");
  const cash = await post("/api/admin/payments/cash-record", { email: "cycle@example.com", plan: "pro", months: 1, amount: 6, currency: "USD", reference: "CASH-TEST-0001", note: "test" }, admin);
  assert.equal(cash.status, 201, "un encaissement cash crée un reçu et une licence");
  assert.match(cash.data.code, /^BK-[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}$/);
  const payments = await fetch(`${base}/api/admin/payments`, { headers: admin });
  assert.equal(payments.status, 200);
  const paymentData = await payments.json();
  assert.equal(paymentData.payments[0].reference, "CASH-TEST-0001");
  assert.equal(paymentData.payments[0].amount, 6);
  assert.match(paymentData.payments[0].invoice_number, /^BK-\d{4}-\d{6}$/);
  const invoice = await fetch(`${base}/api/admin/payments/${cash.data.payment.id}/invoice`, { headers: admin });
  assert.equal(invoice.status, 200, "le reçu est accessible à l'administrateur");
  assert.equal((await invoice.json()).invoice.amount, 6);
  assert.equal((await fetch(`${base}/api/admin/payments/${cash.data.payment.id}/invoice`)).status, 403, "le reçu exige le jeton administrateur");
  const month = new Date().toISOString().slice(0, 7);
  const report = await fetch(`${base}/api/admin/reports/monthly?month=${month}`, { headers: admin });
  assert.equal(report.status, 200);
  assert.equal((await report.json()).rows.find(r => r.currency === "USD").received, 6);
  assert.equal((await fetch(`${base}/api/admin/reports/monthly?month=invalid`, { headers: admin })).status, 400);
  const historyResponse = await fetch(`${base}/api/admin/users/${paymentData.payments[0].user_id}/history`, { headers: admin });
  assert.equal(historyResponse.status, 200, "l'historique client est accessible avec le jeton administrateur");
  const history = await historyResponse.json();
  assert.equal(history.payments.length, 1);
  assert.equal(history.payments[0].invoice_number, paymentData.payments[0].invoice_number);
  assert.equal(history.subscriptions.length >= 1, true, "l'historique conserve les abonnements successifs");
  assert.equal((await fetch(`${base}/api/admin/users/${paymentData.payments[0].user_id}/history`)).status, 403, "l'historique exige le jeton administrateur");
  const notificationStatus = await fetch(`${base}/api/admin/notifications/status`, { headers: admin });
  assert.equal(notificationStatus.status, 200);
  assert.equal((await notificationStatus.json()).configured, false, "aucun fournisseur d’e-mail n’est présumé configuré");
  assert.equal((await fetch(`${base}/api/admin/notifications/status`)).status, 403, "l’état des notifications exige super_admin");
  const sendWithoutProvider = await post("/api/admin/notifications/send-expiry", { days: 7 }, admin);
  assert.equal(sendWithoutProvider.status, 503, "aucun rappel n’est envoyé sans webhook configuré");
  const notificationLog = await fetch(`${base}/api/admin/notifications/log`, { headers: admin });
  assert.equal(notificationLog.status, 200);
  const expiry = await fetch(`${base}/api/admin/reports/expiring?days=7`, { headers: admin });
  assert.equal(expiry.status, 200);
  assert.equal((await fetch(`${base}/api/admin/reports/expiring?days=180`, { headers: admin })).status, 400);
  const csvResponse = await fetch(`${base}/api/admin/reports/accounting.csv?month=${month}`, { headers: admin });
  assert.equal(csvResponse.status, 200);
  assert.match(csvResponse.headers.get("content-type"), /text\/csv/);
  assert.match(await csvResponse.text(), /numero_recu/);
  assert.equal((await fetch(`${base}/api/admin/reports/accounting.csv?month=${month}`)).status, 403, "l'export comptable exige le jeton administrateur");
  assert.equal((await post("/api/admin/payments/cash-record", { email: "cycle@example.com", plan: "pro", months: 1, amount: 6, currency: "USD", reference: "CASH-TEST-0002" }, {})).status, 403, "l'enregistrement cash exige super_admin");
  assert.equal((await post(`/api/admin/payments/${cash.data.payment.id}/refund`, { reason: "test refund" }, {})).status, 403, "le remboursement exige super_admin");
  assert.equal((await post(`/api/admin/payments/${cash.data.payment.id}/refund`, { reason: "test refund" }, admin)).status, 200);
  const refunded = await fetch(`${base}/api/admin/payments/${cash.data.payment.id}/invoice`, { headers: admin });
  assert.equal((await refunded.json()).invoice.status, "refunded");
  assert.equal((await post(`/api/admin/payments/${cash.data.payment.id}/refund`, { reason: "duplicate" }, admin)).status, 409, "un remboursement ne peut être enregistré deux fois");
  const afterRefund = await fetch(`${base}/api/admin/reports/monthly?month=${month}`, { headers: admin });
  const refundRow = (await afterRefund.json()).rows.find(r => r.currency === "USD");
  assert.equal(refundRow.received, 0, "les remboursements sont exclus du total encaissé");
  assert.equal(refundRow.refunded, 6, "le montant remboursé est présenté séparément");
  assert.equal((await post("/api/admin/subscriptions/activate", { email: "cycle@example.com", plan: "pro", months: 1 }, admin)).status, 200);
  assert.equal((await post("/api/account/offline-lease", { machineId: "machine-first-123" }, auth)).status, 200);
  assert.equal((await post("/api/admin/subscriptions/activate", { email: "cycle@example.com", plan: "premium", months: 1 }, admin)).status, 200);
  assert.equal((await post("/api/account/offline-lease", { machineId: "machine-second-456" }, auth)).status, 409, "le renouvellement conserve la liaison machine");
  assert.equal((await post("/api/admin/subscriptions/transfer-machine", { email: "cycle@example.com", reason: "test" }, admin)).status, 200);
  assert.equal((await post("/api/account/offline-lease", { machineId: "machine-second-456" }, auth)).status, 200, "le transfert permet le nouveau bail");
  const revoked = await post("/api/admin/subscriptions/revoke", { email: "cycle@example.com", reason: "test" }, admin);
  assert.equal(revoked.status, 200);
  assert.equal(revoked.data.user.plan, "free");
  assert.equal((await post("/api/admin/subscriptions/revoke", { email: "cycle@example.com" }, {})).status, 403, "la révocation exige le secret administrateur");
});
