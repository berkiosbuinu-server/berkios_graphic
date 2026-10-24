import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { randomBytes, scryptSync, timingSafeEqual, createHash } from "node:crypto";
import { loadLicenseKeys, signLease } from "./license-signing.js";

const VERSION = "0.7.91";
const BACKEND_DIR = dirname(fileURLToPath(import.meta.url));
const licenseKeys = loadLicenseKeys();
const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || "127.0.0.1";
const DB_PATH = process.env.BERKIOS_DB || "./berkios-users.sqlite";
const db = new DatabaseSync(DB_PATH);
db.exec(`
 PRAGMA journal_mode=WAL;
 PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL
 );
 CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
 );
 CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan TEXT NOT NULL CHECK(plan IN ('free','pro','premium')), status TEXT NOT NULL DEFAULT 'active',
  starts_at TEXT NOT NULL, expires_at TEXT, grace_until TEXT, source TEXT NOT NULL DEFAULT 'free',
  provider TEXT NOT NULL DEFAULT 'manual', created_at TEXT NOT NULL
 );
 CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT NOT NULL UNIQUE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  plan TEXT NOT NULL CHECK(plan IN ('pro','premium')), duration_months INTEGER NOT NULL DEFAULT 1,
  machine_id TEXT, status TEXT NOT NULL DEFAULT 'unused', issued_by TEXT NOT NULL DEFAULT 'super_admin',
  created_at TEXT NOT NULL, redeemed_at TEXT
 );
 CREATE TABLE IF NOT EXISTS cash_payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
  amount REAL NOT NULL CHECK(amount > 0), currency TEXT NOT NULL CHECK(currency IN ('USD','CDF')),
  plan TEXT NOT NULL CHECK(plan IN ('pro','premium')), months INTEGER NOT NULL,
  reference TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'received',
  received_by TEXT NOT NULL DEFAULT 'super_admin', created_at TEXT NOT NULL, invoice_number TEXT,
  refunded_at TEXT, refund_reason TEXT
 );
 CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT, subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, window_days INTEGER NOT NULL, channel TEXT NOT NULL DEFAULT 'email', recipient TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, sent_at TEXT, UNIQUE(subscription_id,kind,window_days,channel)
 );
 CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target_user_id INTEGER,
  details TEXT, created_at TEXT NOT NULL
 );
`);
// Migrate the earlier local-development database without discarding accounts.
const cols = (table) => db.prepare(`PRAGMA table_info(${table})`).all().map(x => x.name);
if (!cols("users").includes("phone")) db.exec("ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT ''");
if (!cols("users").includes("role")) db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
if (!cols("subscriptions").includes("machine_id")) db.exec("ALTER TABLE subscriptions ADD COLUMN machine_id TEXT");
if (!cols("licenses").includes("payment_id")) db.exec("ALTER TABLE licenses ADD COLUMN payment_id INTEGER");
if (!cols("cash_payments").includes("invoice_number")) db.exec("ALTER TABLE cash_payments ADD COLUMN invoice_number TEXT");
if (!cols("cash_payments").includes("refunded_at")) db.exec("ALTER TABLE cash_payments ADD COLUMN refunded_at TEXT");
if (!cols("cash_payments").includes("refund_reason")) db.exec("ALTER TABLE cash_payments ADD COLUMN refund_reason TEXT");
// Stable invoice numbers for older payment rows; the unique index prevents duplicate numbers.
for (const row of db.prepare("SELECT id,created_at FROM cash_payments WHERE invoice_number IS NULL OR invoice_number='' ORDER BY id").all()) {
 const year=String(new Date(row.created_at).getUTCFullYear()||new Date().getUTCFullYear());
 db.prepare("UPDATE cash_payments SET invoice_number=? WHERE id=?").run(`BK-${year}-${String(row.id).padStart(6,"0")}`,row.id);
}
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_cash_payments_invoice_number ON cash_payments(invoice_number)");
// Existing legacy accounts get a deterministic, non-empty placeholder phone until they update their profile.
db.exec("UPDATE users SET phone='legacy-' || id || '@invalid.berkios' WHERE phone='' OR phone IS NULL");
const nowIso = () => new Date().toISOString();
const plans = {
 free: { label: "Free", monthlyUsd: 0, components: 12, maxWidgetsPerProject: 12, maxProjects: 3, restSources: 1, mobileBuild: false, coworking: false, dailyCreditMinutes: 120 },
 pro: { label: "Pro", monthlyUsd: 6, regularMonthlyUsd: 7.5, discountPercent: 20, components: 150, maxWidgetsPerProject: 150, maxProjects: 25, restSources: 10, mobileBuild: true, coworking: false, dailyCreditMinutes: null },
 premium: { label: "Premium", monthlyUsd: 20, regularMonthlyUsd: 25, discountPercent: 20, components: -1, maxWidgetsPerProject: -1, maxProjects: -1, restSources: -1, mobileBuild: true, coworking: true, dailyCreditMinutes: null }
};
function allowedOrigin(origin) {
 if (!origin) return "";
 try { const u = new URL(origin); if (["localhost", "127.0.0.1"].includes(u.hostname) && [5173,4173].includes(Number(u.port))) return origin;
  const configured = (process.env.BERKIOS_CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  return configured.includes(origin) ? origin : "";
 } catch { return ""; }
}
function send(res,status,body,origin="") {
 const headers={"Content-Type":"application/json; charset=utf-8","Access-Control-Allow-Headers":"Content-Type, Authorization, X-Berkios-Admin-Token","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Cache-Control":"no-store","Vary":"Origin","X-Content-Type-Options":"nosniff"};
 const cors=allowedOrigin(origin); if(cors) headers["Access-Control-Allow-Origin"]=cors;
 res.writeHead(status,headers); res.end(JSON.stringify(body));
}
async function readBody(req) { let raw=""; for await (const chunk of req) { raw+=chunk; if(raw.length>32000) throw new Error("Requête trop volumineuse."); } try{return JSON.parse(raw||"{}");}catch{throw new Error("JSON invalide.");} }
function validEmail(v){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)&&v.length<=254;}
function validPhone(v){return /^\+?[0-9][0-9 ()-]{6,23}$/.test(v)&&v.replace(/\D/g,"").length>=7;}
function normalizePhone(v){return v.replace(/[ ()-]/g,"");}
function makeHash(password,salt){return scryptSync(password,salt,64).toString("hex");}
function hashToken(s){return createHash("sha256").update(s).digest("hex");}
function tokenFor(userId){const token=randomBytes(32).toString("base64url");db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").run(hashToken(token),userId,Date.now()+30*24*60*60*1000);return token;}
function activeSubscription(userId){
 let sub=db.prepare("SELECT * FROM subscriptions WHERE user_id=? ORDER BY id DESC LIMIT 1").get(userId);
 if(!sub){db.prepare("INSERT INTO subscriptions(user_id,plan,status,starts_at,source,provider,created_at) VALUES(?,'free','active',?,'free','manual',?)").run(userId,nowIso(),nowIso());sub=db.prepare("SELECT * FROM subscriptions WHERE user_id=? ORDER BY id DESC LIMIT 1").get(userId);}
 if(sub.plan!=="free" && sub.expires_at && Date.now()>Date.parse(sub.expires_at)){
   const graceUntil=sub.grace_until || new Date(Date.parse(sub.expires_at)+48*60*60*1000).toISOString();
   if(!sub.grace_until) db.prepare("UPDATE subscriptions SET grace_until=? WHERE id=?").run(graceUntil,sub.id);
   if(Date.now()>Date.parse(graceUntil)){
     db.prepare("UPDATE subscriptions SET plan='free',status='expired',source='automatic-downgrade',provider='system' WHERE id=?").run(sub.id);
     sub=db.prepare("SELECT * FROM subscriptions WHERE id=?").get(sub.id);
   } else { sub={...sub,grace_until:graceUntil,status:"grace"}; }
 }
 return sub;
}
function userView(user){const sub=activeSubscription(user.id);return {id:user.id,email:user.email,phone:user.phone,role:user.role||"user",createdAt:user.created_at,plan:sub.plan,subscription:{status:sub.status,startsAt:sub.starts_at,expiresAt:sub.expires_at,graceUntil:sub.grace_until,source:sub.source,provider:sub.provider},machineBound:Boolean(sub.machine_id),machineId:sub.machine_id||null,pricing:plans[sub.plan]};}
function currentUser(req){const auth=req.headers.authorization||"";const token=auth.startsWith("Bearer ")?auth.slice(7):"";if(!token)return null;return db.prepare("SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?").get(hashToken(token),Date.now())||null;}
function requireAdmin(req){const secret=process.env.BERKIOS_SUPER_ADMIN_TOKEN||"";const supplied=String(req.headers["x-berkios-admin-token"]||"");const a=Buffer.from(supplied),b=Buffer.from(secret);return Boolean(secret)&&a.length===b.length&&timingSafeEqual(a,b);}
function audit(actor,action,userId,details={}){db.prepare("INSERT INTO audit_log(actor,action,target_user_id,details,created_at) VALUES(?,?,?,?,?)").run(actor,action,userId,JSON.stringify(details),nowIso());}
function newLicenseCode(){return `BK-${randomBytes(3).toString("hex")}-${randomBytes(3).toString("hex")}-${randomBytes(3).toString("hex")}`.toUpperCase();}
function addSubscription(userId,plan,months=1,source="manual",provider="cash"){
 const previous=db.prepare("SELECT machine_id FROM subscriptions WHERE user_id=? ORDER BY id DESC LIMIT 1").get(userId);
 const start=new Date(); const expiry=plan==="free"?null:new Date(start.getTime()); if(expiry) expiry.setUTCMonth(expiry.getUTCMonth()+months);
 const expiresAt=expiry?expiry.toISOString():null;
 // Une activation/renouvellement conserve la liaison machine; seul le transfert admin peut la réinitialiser.
 db.prepare("INSERT INTO subscriptions(user_id,plan,status,starts_at,expires_at,grace_until,source,provider,created_at,machine_id) VALUES(?,?,'active',?,?,NULL,?,?,?,?)").run(userId,plan,start.toISOString(),expiresAt,source,provider,nowIso(),previous?.machine_id||null);
 return activeSubscription(userId);
}
const server=createServer(async(req,res)=>{
 const origin=String(req.headers.origin||""); const reply=(s,b)=>send(res,s,b,origin);
 if(req.method==="OPTIONS"){const cors=allowedOrigin(origin);const h={"Access-Control-Allow-Headers":"Content-Type, Authorization, X-Berkios-Admin-Token","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Vary":"Origin"};if(cors)h["Access-Control-Allow-Origin"]=cors;res.writeHead(204,h);return res.end();}
 const url=new URL(req.url||"/",`http://${req.headers.host||`${HOST}:${PORT}`}`);
 try{
  if(req.method==="GET"&&url.pathname==="/admin"){
   const html=readFileSync(join(BACKEND_DIR,"admin-dashboard.html"));
   res.writeHead(200,{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"});return res.end(html);
  }
  if(req.method==="GET"&&url.pathname==="/api/health")return reply(200,{ok:true,service:"berkios-account-backend",version:VERSION,storage:"sqlite",features:["accounts","subscriptions","cash-payment-ledger","cash-licenses","machine-binding","admin-activation","provider-adapters-disabled-until-configured","signed-offline-leases","admin-dashboard","printable-invoices","refund-register","monthly-revenue-report","client-history","expiry-alerts","accounting-csv-export","expiry-notification-outbox","configured-notification-webhook"]});
  if(req.method==="GET"&&url.pathname==="/api/admin/users"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const q=String(url.searchParams.get("q")||"").trim().toLowerCase().slice(0,200);
   const rows=q?db.prepare("SELECT * FROM users WHERE lower(email) LIKE ? OR phone LIKE ? ORDER BY id DESC LIMIT 100").all(`%${q}%`,`%${q}%`):db.prepare("SELECT * FROM users ORDER BY id DESC LIMIT 100").all();
   return reply(200,{ok:true,users:rows.map(userView),limit:100});
  }
  if(req.method==="GET"&&url.pathname==="/api/admin/audit"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const rows=db.prepare("SELECT id,actor,action,target_user_id,details,created_at FROM audit_log ORDER BY id DESC LIMIT 100").all();
   return reply(200,{ok:true,events:rows.map(r=>({...r,details: (()=>{try{return JSON.parse(r.details||"{}")}catch{return {}}})()}))});
  }
  if(req.method==="GET"&&url.pathname==="/api/admin/payments"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const rows=db.prepare("SELECT p.id,p.user_id,u.email,p.amount,p.currency,p.plan,p.months,p.reference,p.note,p.status,p.received_by,p.created_at,p.invoice_number,p.refunded_at,p.refund_reason FROM cash_payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100").all();
   const totals=db.prepare("SELECT currency,SUM(amount) AS total,COUNT(*) AS count FROM cash_payments WHERE status='received' GROUP BY currency").all();
   return reply(200,{ok:true,payments:rows,totals,limit:100});
  }
  if(req.method==="GET"&&url.pathname==="/api/admin/reports/expiring"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const daysRaw=Number(url.searchParams.get("days")||7);
   if(!Number.isInteger(daysRaw)||daysRaw<1||daysRaw>90)return reply(400,{error:"La période doit être comprise entre 1 et 90 jours."});
   const now=nowIso(),until=new Date(Date.now()+daysRaw*86400000).toISOString();
   const rows=db.prepare("SELECT u.id AS user_id,u.email,u.phone,s.id AS subscription_id,s.plan,s.status,s.starts_at,s.expires_at,s.grace_until,s.source,s.provider FROM subscriptions s JOIN users u ON u.id=s.user_id WHERE s.id=(SELECT MAX(s2.id) FROM subscriptions s2 WHERE s2.user_id=s.user_id) AND s.plan IN ('pro','premium') AND s.expires_at IS NOT NULL AND s.expires_at>=? AND s.expires_at<=? ORDER BY s.expires_at ASC").all(now,until);
   return reply(200,{ok:true,days:daysRaw,asOf:now,count:rows.length,subscriptions:rows.map(r=>({...r,daysRemaining:Math.max(0,Math.ceil((Date.parse(r.expires_at)-Date.now())/86400000))}))});
  }
  if(req.method==="GET"&&url.pathname==="/api/admin/notifications/status"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   return reply(200,{ok:true,configured:Boolean(process.env.BERKIOS_NOTIFICATION_API_URL),channel:"email-webhook",message:process.env.BERKIOS_NOTIFICATION_API_URL?"Le webhook de notification est configuré.":"Aucun envoi réel : configurez BERKIOS_NOTIFICATION_API_URL (HTTPS) et, si nécessaire, BERKIOS_NOTIFICATION_API_TOKEN."});
  }
  if(req.method==="POST"&&url.pathname==="/api/admin/notifications/send-expiry"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const b=await readBody(req),days=Number(b.days||7);
   if(!Number.isInteger(days)||days<1||days>90)return reply(400,{error:"La période doit être comprise entre 1 et 90 jours."});
   const endpoint=String(process.env.BERKIOS_NOTIFICATION_API_URL||"").trim();
   if(!endpoint)return reply(503,{error:"Envoi désactivé : configurez BERKIOS_NOTIFICATION_API_URL sur le serveur avant d’envoyer des rappels."});
   let endpointUrl;try{endpointUrl=new URL(endpoint)}catch{return reply(500,{error:"BERKIOS_NOTIFICATION_API_URL n’est pas une URL valide."});}
   if(endpointUrl.protocol!=="https:" && !(["localhost","127.0.0.1"].includes(endpointUrl.hostname) && process.env.NODE_ENV!=="production"))return reply(500,{error:"Le webhook de notification doit utiliser HTTPS en production."});
   const now=nowIso(),until=new Date(Date.now()+days*86400000).toISOString();
   const rows=db.prepare("SELECT u.id AS user_id,u.email,u.phone,s.id AS subscription_id,s.plan,s.expires_at FROM subscriptions s JOIN users u ON u.id=s.user_id WHERE s.id=(SELECT MAX(s2.id) FROM subscriptions s2 WHERE s2.user_id=s.user_id) AND s.plan IN ('pro','premium') AND s.expires_at IS NOT NULL AND s.expires_at>=? AND s.expires_at<=? ORDER BY s.expires_at ASC").all(now,until);
   let sent=0,skipped=0,failed=0;const results=[];
   for(const row of rows){
    const existing=db.prepare("SELECT id,status FROM notifications WHERE subscription_id=? AND kind='expiry-reminder' AND window_days=? AND channel='email'").get(row.subscription_id,days);
    if(existing?.status==='sent'){skipped++;continue;}
    const ins=existing?{lastInsertRowid:existing.id}:db.prepare("INSERT INTO notifications(subscription_id,kind,window_days,channel,recipient,status,created_at) VALUES(?,'expiry-reminder',?,'email',?,'pending',?)").run(row.subscription_id,days,row.email,now);
    const notificationId=Number(ins.lastInsertRowid);
    const daysRemaining=Math.max(0,Math.ceil((Date.parse(row.expires_at)-Date.now())/86400000));
    const payload={to:row.email,subject:`Votre abonnement BERKIOS ${row.plan.toUpperCase()} arrive à échéance`,text:`Bonjour,\n\nVotre abonnement BERKIOS ${row.plan.toUpperCase()} expire le ${row.expires_at}. Il reste environ ${daysRemaining} jour(s). Pour continuer à utiliser les fonctions de votre offre, veuillez contacter l’équipe BERKIOS pour renouveler votre abonnement.\n\nL’équipe BERKIOS`,template:"berkios-subscription-expiry",userId:row.user_id,subscriptionId:row.subscription_id,expiresAt:row.expires_at,daysRemaining};
    try{
     db.prepare("UPDATE notifications SET attempts=attempts+1,status='pending',last_error='' WHERE id=?").run(notificationId);
     const headers={"Content-Type":"application/json"};if(process.env.BERKIOS_NOTIFICATION_API_TOKEN)headers.Authorization=`Bearer ${process.env.BERKIOS_NOTIFICATION_API_TOKEN}`;
     const response=await fetch(endpoint,{method:"POST",headers,body:JSON.stringify(payload),signal:AbortSignal.timeout(8000)});
     if(!response.ok)throw new Error(`Webhook HTTP ${response.status}`);
     db.prepare("UPDATE notifications SET status='sent',sent_at=?,last_error='' WHERE id=?").run(nowIso(),notificationId);sent++;results.push({email:row.email,status:"sent"});
     audit("super_admin","expiry-notification.sent",row.user_id,{notificationId,subscriptionId:row.subscription_id,days});
    }catch(error){const message=String(error?.message||"Erreur d’envoi").slice(0,500);db.prepare("UPDATE notifications SET status='failed',last_error=? WHERE id=?").run(message,notificationId);failed++;results.push({email:row.email,status:"failed",error:message});audit("super_admin","expiry-notification.failed",row.user_id,{notificationId,error:message});}
   }
   return reply(200,{ok:true,days,total:rows.length,sent,skipped,failed,results,message:`Rappels envoyés : ${sent}; déjà envoyés : ${skipped}; échecs : ${failed}.`});
  }
  if(req.method==="GET"&&url.pathname==="/api/admin/notifications/log"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const rows=db.prepare("SELECT n.id,n.kind,n.window_days,n.channel,n.recipient,n.status,n.attempts,n.last_error,n.created_at,n.sent_at,u.id AS user_id FROM notifications n JOIN subscriptions s ON s.id=n.subscription_id JOIN users u ON u.id=s.user_id ORDER BY n.id DESC LIMIT 100").all();
   return reply(200,{ok:true,notifications:rows});
  }
  if(req.method==="GET"&&url.pathname==="/api/admin/reports/accounting.csv"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const month=String(url.searchParams.get("month")||new Date().toISOString().slice(0,7));
   if(!/^\d{4}-(0[1-9]|1[0-2])$/.test(month))return reply(400,{error:"Mois invalide. Utilisez AAAA-MM."});
   const rows=db.prepare("SELECT p.id,p.invoice_number,p.created_at,u.email,u.phone,p.plan,p.months,p.amount,p.currency,p.reference,p.status,p.refunded_at,p.refund_reason,p.received_by,p.note FROM cash_payments p JOIN users u ON u.id=p.user_id WHERE substr(p.created_at,1,7)=? ORDER BY p.created_at,p.id").all(month);
   const cell=v=>{let x=String(v??'');if(/^[=+\-@\t\r]/.test(x))x="'"+x;return '"'+x.replace(/"/g,'""')+'"'};
   const headers=["id_paiement","numero_recu","date","email_client","telephone","offre","duree_mois","montant","devise","reference","statut","date_remboursement","motif_remboursement","encaisse_par","note"];
   const csv='\uFEFF'+[headers,...rows.map(r=>[r.id,r.invoice_number,r.created_at,r.email,r.phone,r.plan,r.months,r.amount,r.currency,r.reference,r.status,r.refunded_at,r.refund_reason,r.received_by,r.note])].map(row=>row.map(cell).join(';')).join('\r\n');
   res.writeHead(200,{"Content-Type":"text/csv; charset=utf-8","Content-Disposition":`attachment; filename="berkios-comptabilite-${month}.csv"`,"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Vary":"Origin"});return res.end(csv);
  }
  if(req.method==="GET"&&/^\/api\/admin\/users\/\d+\/history$/.test(url.pathname)){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const userId=Number(url.pathname.split("/")[4]),user=db.prepare("SELECT id,email,phone,role,created_at FROM users WHERE id=?").get(userId);
   if(!user)return reply(404,{error:"Compte client introuvable."});
   const subscriptions=db.prepare("SELECT id,plan,status,starts_at,expires_at,grace_until,source,provider,created_at,machine_id FROM subscriptions WHERE user_id=? ORDER BY id DESC LIMIT 200").all(userId);
   const payments=db.prepare("SELECT id,invoice_number,amount,currency,plan,months,reference,note,status,received_by,created_at,refunded_at,refund_reason FROM cash_payments WHERE user_id=? ORDER BY id DESC LIMIT 200").all(userId);
   const totals=db.prepare("SELECT currency,SUM(CASE WHEN status='received' THEN amount ELSE 0 END) AS received,SUM(CASE WHEN status='refunded' THEN amount ELSE 0 END) AS refunded,COUNT(*) AS operations FROM cash_payments WHERE user_id=? GROUP BY currency ORDER BY currency").all(userId);
   audit("super_admin","client-history.viewed",userId,{});
   return reply(200,{ok:true,user,subscriptions,payments,totals});
  }
  if(req.method==="GET"&&url.pathname==="/api/admin/reports/monthly"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const month=String(url.searchParams.get("month")||new Date().toISOString().slice(0,7));
   if(!/^\d{4}-(0[1-9]|1[0-2])$/.test(month))return reply(400,{error:"Mois invalide. Utilisez AAAA-MM."});
   const rows=db.prepare("SELECT currency,SUM(CASE WHEN status='received' THEN amount ELSE 0 END) AS received,COUNT(CASE WHEN status='received' THEN 1 END) AS payments, SUM(CASE WHEN status='refunded' THEN amount ELSE 0 END) AS refunded,COUNT(CASE WHEN status='refunded' THEN 1 END) AS refunds FROM cash_payments WHERE substr(created_at,1,7)=? GROUP BY currency ORDER BY currency").all(month);
   return reply(200,{ok:true,month,rows});
  }
  if(req.method==="GET"&&/^\/api\/admin\/payments\/\d+\/invoice$/.test(url.pathname)){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const id=Number(url.pathname.split("/")[4]);
   const row=db.prepare("SELECT p.id,p.user_id,u.email,u.phone,p.amount,p.currency,p.plan,p.months,p.reference,p.note,p.status,p.received_by,p.created_at,p.invoice_number,p.refunded_at,p.refund_reason FROM cash_payments p JOIN users u ON u.id=p.user_id WHERE p.id=?").get(id);
   if(!row)return reply(404,{error:"Facture ou reçu introuvable."});
   return reply(200,{ok:true,invoice:{...row,issuer:"BERKIOS",documentType:row.status==='refunded'?'Avoir / paiement remboursé':'Reçu de paiement',generatedAt:nowIso(),disclaimer:"Document généré par le registre BERKIOS. Conservez la référence d'encaissement."}});
  }
  if(req.method==="POST"&&/^\/api\/admin\/payments\/\d+\/refund$/.test(url.pathname)){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const id=Number(url.pathname.split("/")[4]),b=await readBody(req),reason=String(b.reason||"").trim().slice(0,500);
   if(reason.length<3)return reply(400,{error:"Le motif du remboursement est obligatoire (3 caractères minimum)."});
   const payment=db.prepare("SELECT * FROM cash_payments WHERE id=?").get(id);
   if(!payment)return reply(404,{error:"Encaissement introuvable."});
   if(payment.status==='refunded')return reply(409,{error:"Cet encaissement est déjà marqué comme remboursé."});
   db.prepare("UPDATE cash_payments SET status='refunded',refunded_at=?,refund_reason=? WHERE id=? AND status='received'").run(nowIso(),reason,id);
   audit("super_admin","cash-payment.refunded",payment.user_id,{paymentId:id,amount:payment.amount,currency:payment.currency,reason});
   return reply(200,{ok:true,paymentId:id,status:"refunded",message:"Remboursement enregistré dans le registre. La révocation de l'abonnement, si nécessaire, doit être effectuée séparément."});
  }
  if(req.method==="GET"&&url.pathname==="/api/payments/providers"){
   return reply(200,{ok:true,onlinePaymentsEnabled:false,providers:[{id:"orange-money",label:"Orange Money",enabled:false},{id:"mpesa",label:"M-Pesa",enabled:false},{id:"airtel-money",label:"Airtel Money",enabled:false},{id:"flutterwave",label:"Flutterwave",enabled:false},{id:"stripe",label:"Stripe",enabled:false}],message:"Connecteurs préparés uniquement. Aucun fournisseur n'est actif avant configuration des identifiants, des signatures de webhook et des tests de bout en bout."});
  }
  if(req.method==="POST"&&["/api/auth/register","/api/auth/login"].includes(url.pathname)){
   const b=await readBody(req), password=String(b.password||""), email=String(b.email||"").trim().toLowerCase(), phone=normalizePhone(String(b.phone||"")), login=String(b.identifier||email||phone).trim().toLowerCase();
   if(password.length<10||password.length>256)return reply(400,{error:"Le mot de passe doit contenir entre 10 et 256 caractères."});
   let user;
   if(url.pathname.endsWith("register")){
    if(!validEmail(email))return reply(400,{error:"Saisissez une adresse e-mail valide."});
    if(!validPhone(phone))return reply(400,{error:"Saisissez un numéro de téléphone valide avec indicatif pays."});
    const salt=randomBytes(16).toString("hex"), hash=makeHash(password,salt);
    try{const r=db.prepare("INSERT INTO users(email,phone,salt,password_hash,role,created_at) VALUES(?,?,?,?,'user',?)").run(email,phone,salt,hash,nowIso());user=db.prepare("SELECT * FROM users WHERE id=?").get(Number(r.lastInsertRowid));addSubscription(user.id,"free",1,"registration","system");}
    catch(e){return reply(409,{error:"Un compte existe déjà avec cet e-mail ou ce téléphone."});}
   }else{
    user=db.prepare("SELECT * FROM users WHERE lower(email)=? OR phone=?").get(login,normalizePhone(String(b.identifier||b.phone||"")));
    const salt=user?.salt||"00000000000000000000000000000000", candidate=makeHash(password,salt), expected=user?.password_hash||"0".repeat(128);
    if(!user||!timingSafeEqual(Buffer.from(candidate,"hex"),Buffer.from(expected,"hex")))return reply(401,{error:"E-mail/téléphone ou mot de passe incorrect."});
   }
   return reply(200,{token:tokenFor(user.id),user:userView(user)});
  }
  if(req.method==="GET"&&url.pathname==="/api/account/me") {const u=currentUser(req);return u?reply(200,{user:userView(u)}):reply(401,{error:"Session absente ou expirée."});}
  if(req.method==="POST"&&url.pathname==="/api/account/logout"){const token=String(req.headers.authorization||"").replace(/^Bearer\s+/,"");if(token)db.prepare("DELETE FROM sessions WHERE token_hash=?").run(hashToken(token));return reply(200,{ok:true});}
  if(req.method==="GET"&&url.pathname==="/api/account/capabilities"){
   const u=currentUser(req);if(!u)return reply(401,{error:"Session absente ou expirée."});const sub=activeSubscription(u.id),p=plans[sub.plan];
   return reply(200,{plan:sub.plan,subscription:{status:sub.status,expiresAt:sub.expires_at,graceUntil:sub.grace_until},capabilities:{components:p.components,maxWidgetsPerProject:p.maxWidgetsPerProject,maxProjects:p.maxProjects,restSources:p.restSources,mobileBuild:p.mobileBuild,coworking:p.coworking,dailyCreditMinutes:p.dailyCreditMinutes},pricing:plans,notice:"Les capacités doivent également être vérifiées par le serveur Bridge avant chaque build et opération protégée."});
  }
  if(req.method==="POST"&&url.pathname==="/api/account/offline-lease"){
   const u=currentUser(req);if(!u)return reply(401,{error:"Connectez-vous avant de demander une licence hors ligne."});
   if(!licenseKeys)return reply(503,{error:"La signature des licences hors ligne n'est pas configurée sur le serveur."});
   const b=await readBody(req),machineId=String(b.machineId||"").trim();
   if(machineId.length<8||machineId.length>256)return reply(400,{error:"Identifiant de machine invalide."});
   const sub=activeSubscription(u.id);const current=db.prepare("SELECT * FROM subscriptions WHERE id=?").get(sub.id);
   if(current.machine_id && current.machine_id!==machineId)return reply(409,{error:"Cet abonnement est déjà lié à une autre machine. Contactez Berkios pour demander un transfert."});
   if(!current.machine_id)db.prepare("UPDATE subscriptions SET machine_id=? WHERE id=? AND (machine_id IS NULL OR machine_id=?)").run(machineId,current.id,machineId);
   const refreshed=db.prepare("SELECT * FROM subscriptions WHERE id=?").get(current.id);
   const issuedAt=Date.now(); const effectiveExpiry=refreshed.plan==="free"?issuedAt+24*60*60*1000:Math.min(Date.parse(refreshed.grace_until||refreshed.expires_at||new Date(issuedAt+24*60*60*1000).toISOString()),issuedAt+24*60*60*1000);
   if(refreshed.plan!=="free" && Number.isFinite(effectiveExpiry) && effectiveExpiry<=issuedAt)return reply(403,{error:"L'abonnement a expiré. Renouvelez-le pour obtenir une licence hors ligne."});
   const payload={issuer:"BERKIOS",version:1,subject:String(u.id),email:u.email,plan:refreshed.plan,status:refreshed.status,machineId,issuedAt,expiresAt:effectiveExpiry,capabilities:plans[refreshed.plan]};
   const lease=signLease(payload,licenseKeys.privateKey);audit(`user:${u.id}`,"offline-lease.issue",u.id,{plan:refreshed.plan,machineId,expiresAt:effectiveExpiry});
   return reply(200,{ok:true,lease,publicKey:licenseKeys.publicKey.export({type:"spki",format:"pem"}).toString(),message:"Licence signée pour cette machine. Durée maximale hors ligne : 24 heures."});
  }
  if(req.method==="POST"&&url.pathname==="/api/licenses/redeem"){
   const u=currentUser(req);if(!u)return reply(401,{error:"Connectez-vous avant d'activer une licence."});const b=await readBody(req),code=String(b.code||"").trim().toUpperCase(),machineId=String(b.machineId||"").trim();
   if(!/^[A-Z0-9-]{10,40}$/.test(code)||machineId.length<8||machineId.length>256)return reply(400,{error:"Code de licence ou identifiant de machine invalide."});
   const lic=db.prepare("SELECT * FROM licenses WHERE code_hash=? AND status='unused'").get(hashToken(code));if(!lic)return reply(409,{error:"Licence invalide, déjà utilisée ou déjà activée."});
   if(lic.user_id&&lic.user_id!==u.id)return reply(403,{error:"Cette licence a été émise pour un autre compte."});
   const bound=db.prepare("SELECT id,user_id FROM licenses WHERE machine_id=? AND status='redeemed' AND user_id<>? LIMIT 1").get(machineId,u.id);
   if(bound && bound.user_id!==u.id)return reply(409,{error:"Cette machine est déjà liée à un autre compte. Contactez Berkios pour un transfert."});
   db.prepare("UPDATE licenses SET user_id=?,machine_id=?,status='redeemed',redeemed_at=? WHERE id=? AND status='unused'").run(u.id,machineId,nowIso(),lic.id);
   addSubscription(u.id,lic.plan,lic.duration_months,"license-code","cash");audit(`user:${u.id}`,"license.redeem",u.id,{plan:lic.plan,machineId});
   return reply(200,{ok:true,user:userView(u),message:"Licence activée pour cette machine."});
  }
  if(req.method==="POST"&&url.pathname==="/api/admin/subscriptions/transfer-machine"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const b=await readBody(req),key=String(b.email||"").trim().toLowerCase(),phone=normalizePhone(String(b.phone||""));
   const u=db.prepare("SELECT * FROM users WHERE lower(email)=? OR phone=?").get(key,phone);if(!u)return reply(404,{error:"Utilisateur introuvable."});
   const sub=activeSubscription(u.id);db.prepare("UPDATE subscriptions SET machine_id=NULL WHERE id=?").run(sub.id);
   audit("super_admin","subscription.machine-transfer-authorized",u.id,{previousMachineId:sub.machine_id||null,requestedReason:String(b.reason||"").slice(0,300)});
   return reply(200,{ok:true,user:userView(u),message:"Liaison réinitialisée. Le compte pourra activer son bail sur la nouvelle machine. Les baux déjà signés peuvent rester valides jusqu'à leur expiration (24 h maximum)."});
  }
  if(req.method==="POST"&&url.pathname==="/api/admin/subscriptions/revoke"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const b=await readBody(req),key=String(b.email||"").trim().toLowerCase(),phone=normalizePhone(String(b.phone||""));
   const u=db.prepare("SELECT * FROM users WHERE lower(email)=? OR phone=?").get(key,phone);if(!u)return reply(404,{error:"Utilisateur introuvable."});
   const sub=activeSubscription(u.id);db.prepare("UPDATE subscriptions SET plan='free',status='revoked',expires_at=NULL,grace_until=NULL,source='admin-revocation',provider='system' WHERE id=?").run(sub.id);
   audit("super_admin","subscription.revoke",u.id,{previousPlan:sub.plan,reason:String(b.reason||"").slice(0,300)});
   return reply(200,{ok:true,user:userView(u),message:"Abonnement révoqué. Les baux hors ligne déjà signés ne peuvent pas être révoqués instantanément et expirent au plus tard sous 24 h."});
  }
  if(req.method==="POST"&&url.pathname==="/api/admin/subscriptions/activate"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});const b=await readBody(req), plan=String(b.plan||""), months=Math.max(1,Math.min(24,Number(b.months||1)));
   if(!["free","pro","premium"].includes(plan))return reply(400,{error:"Offre inconnue."});const key=String(b.email||"").trim().toLowerCase(),phone=normalizePhone(String(b.phone||""));const u=db.prepare("SELECT * FROM users WHERE lower(email)=? OR phone=?").get(key,phone);if(!u)return reply(404,{error:"Utilisateur introuvable."});
   addSubscription(u.id,plan,months,"super-admin","manual");audit("super_admin","subscription.activate",u.id,{plan,months});return reply(200,{ok:true,user:userView(u)});
  }
  if(req.method==="POST"&&url.pathname==="/api/admin/payments/cash-record"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});
   const b=await readBody(req), email=String(b.email||"").trim().toLowerCase(), plan=String(b.plan||""), months=Number(b.months||1), amount=Number(b.amount), currency=String(b.currency||"USD").toUpperCase(), reference=String(b.reference||"").trim().slice(0,120), note=String(b.note||"").trim().slice(0,500);
   if(!["pro","premium"].includes(plan))return reply(400,{error:"L'encaissement doit correspondre à une offre Pro ou Premium."});
   if(!Number.isInteger(months)||months<1||months>24)return reply(400,{error:"La durée doit être comprise entre 1 et 24 mois."});
   if(!Number.isFinite(amount)||amount<=0||amount>1_000_000_000)return reply(400,{error:"Le montant doit être positif et valide."});
   if(!["USD","CDF"].includes(currency))return reply(400,{error:"Devise acceptée : USD ou CDF."});
   if(reference.length<3)return reply(400,{error:"Une référence de reçu ou d'encaissement (3 caractères minimum) est obligatoire."});
   const u=db.prepare("SELECT * FROM users WHERE lower(email)=?").get(email);if(!u)return reply(404,{error:"Compte introuvable. Recherchez le compte avant d'enregistrer le paiement."});
   if(db.prepare("SELECT id FROM cash_payments WHERE currency=? AND reference=?").get(currency,reference))return reply(409,{error:"Cette référence d'encaissement existe déjà pour cette devise."});
   const code=newLicenseCode();
   try {
    db.exec("BEGIN IMMEDIATE");
    const payment=db.prepare("INSERT INTO cash_payments(user_id,amount,currency,plan,months,reference,note,status,received_by,created_at) VALUES(?,?,?,?,?,?,?,'received','super_admin',?)").run(u.id,amount,currency,plan,months,reference,note,nowIso());
    const paymentId=Number(payment.lastInsertRowid);
    const invoiceNumber=`BK-${new Date().getUTCFullYear()}-${String(paymentId).padStart(6,"0")}`;
    db.prepare("UPDATE cash_payments SET invoice_number=? WHERE id=?").run(invoiceNumber,paymentId);
    db.prepare("INSERT INTO licenses(code_hash,user_id,plan,duration_months,status,issued_by,created_at,payment_id) VALUES(?,?,?,?,'unused','super_admin',?,?)").run(hashToken(code),u.id,plan,months,nowIso(),paymentId);
    audit("super_admin","cash-payment.recorded",u.id,{paymentId,amount,currency,plan,months,reference});
    audit("super_admin","license.issue.cash-payment",u.id,{paymentId,plan,months});
    db.exec("COMMIT");
    return reply(201,{ok:true,payment:{id:paymentId,userId:u.id,email:u.email,amount,currency,plan,months,reference,status:"received",invoiceNumber,createdAt:nowIso()},code,message:"Encaissement enregistré et code créé. Le code ne sera plus récupérable après fermeture de cette réponse."});
   } catch(e) { try{db.exec("ROLLBACK")}catch{} throw e; }
  }
  if(req.method==="POST"&&url.pathname==="/api/admin/licenses/issue"){
   if(!requireAdmin(req))return reply(403,{error:"Accès super_admin refusé. Configurez BERKIOS_SUPER_ADMIN_TOKEN."});const b=await readBody(req),plan=String(b.plan||""),months=Math.max(1,Math.min(24,Number(b.months||1))),key=String(b.email||"").trim().toLowerCase(),phone=normalizePhone(String(b.phone||""));
   if(!["pro","premium"].includes(plan))return reply(400,{error:"Une licence payante doit être Pro ou Premium."});const u=db.prepare("SELECT * FROM users WHERE lower(email)=? OR phone=?").get(key,phone);if(!u)return reply(404,{error:"Utilisateur introuvable."});
   const code=newLicenseCode();db.prepare("INSERT INTO licenses(code_hash,user_id,plan,duration_months,status,issued_by,created_at) VALUES(?,?,?,?,'unused','super_admin',?)").run(hashToken(code),u.id,plan,months,nowIso());audit("super_admin","license.issue",u.id,{plan,months});return reply(201,{ok:true,code,plan,months,email:u.email,message:"Remettez ce code à l'utilisateur après paiement cash. Le code ne s'affiche qu'une seule fois."});
  }
  if(req.method==="POST"&&url.pathname==="/api/account/plan")return reply(410,{error:"Le changement de plan libre-service est désactivé. L'abonnement doit être activé par Berkios ou par un code de licence valide."});
  // Provider-ready entry point: providers are intentionally not enabled until credentials/webhooks are configured.
  if(req.method==="POST"&&url.pathname==="/api/payments/checkout"){
   const u=currentUser(req);if(!u)return reply(401,{error:"Connectez-vous avant de payer."});const b=await readBody(req),plan=String(b.plan||""),provider=String(b.provider||"");if(!["pro","premium"].includes(plan))return reply(400,{error:"Offre payante inconnue."});
   return reply(501,{error:"Les paiements en ligne seront activés ultérieurement.",provider,plan,providers:["stripe","flutterwave","orange-money","mpesa","airtel-money"],integration:{createCheckout:"POST /api/payments/checkout",webhook:"POST /api/payments/webhooks/:provider",verifyPayment:"server-side signature verification required"}});
  }
  return reply(404,{error:"Route inconnue."});
 }catch(error){console.error("BERKIOS API error",error);return reply(400,{error:error instanceof Error?error.message:"Requête invalide."});}
});
server.listen(PORT,HOST,()=>console.log(`BERKIOS backend v${VERSION} écoute sur http://${HOST}:${PORT} (SQLite: ${DB_PATH})`));
function shutdown(){try{db.close();}finally{server.close(()=>process.exit(0));}}
process.on("SIGINT",shutdown);process.on("SIGTERM",shutdown);
