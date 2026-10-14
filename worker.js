/**
 * SociaBuzz -> Roblox Bridge (Cloudflare Worker + D1)  -- v2
 *
 * Secrets / vars yang dipakai:
 *   WEBHOOK_KEY    wajib  - key untuk webhook SociaBuzz
 *   ROBLOX_API_KEY wajib  - key untuk /api/pull, /api/ack, /api/top (header x-api-key)
 *   ADMIN_KEY      wajib  - key untuk /admin/* (header x-admin-key atau ?key=)
 *   DEBUG_WEBHOOK  opsional - "1" untuk console.log payload mentah
 *
 * Binding D1: DB
 */

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const WEBHOOK_BASE = "/webhook/sociabuzz";
const MAX_ATTEMPTS = 8;
const LEASE_MS = 45_000;
const LOG_BODY_MAX = 16_000;
const LOG_KEEP_ROWS = 300;
const SENSITIVE_HEADERS = new Set([
  "authorization", "cookie", "x-webhook-key", "x-webhook-token",
  "x-api-key", "x-admin-key",
]);

const encoder = new TextEncoder();

/* ------------------------------------------------------------------ */
/* Helpers umum                                                        */
/* ------------------------------------------------------------------ */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function isObj(v) {
  return v !== null && typeof v === "object";
}

function clampInt(value, min, max, fallback = min) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function cleanText(value, fallback = "", max = 250) {
  const s = String(value ?? "")
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return (s || fallback).slice(0, max);
}

function safeEqual(a, b) {
  const x = encoder.encode(String(a ?? ""));
  const y = encoder.encode(String(b ?? ""));
  if (!x.length || x.length !== y.length) return false;
  let r = 0;
  for (let i = 0; i < x.length; i++) r |= x[i] ^ y[i];
  return r === 0;
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

async function sha256Hex(text) {
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function parseAmount(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(0, Math.floor(value));
  }

  let raw = String(value ?? "").trim();
  if (!raw) return 0;
  raw = raw.replace(/[^0-9.,-]/g, "");
  if (!raw) return 0;

  const lastDot = raw.lastIndexOf(".");
  const lastComma = raw.lastIndexOf(",");
  const lastSep = Math.max(lastDot, lastComma);

  // 10000.00 / 10.000,00 -> desimal. Satu pemisah + tepat 3 digit -> pemisah ribuan.
  if (lastSep >= 0) {
    const fractionLength = raw.length - lastSep - 1;
    const hasBoth = lastDot >= 0 && lastComma >= 0;
    const thousandsPattern = /^-?\d{1,3}([.,]\d{3})+$/;

    if (fractionLength > 0 && fractionLength <= 2 && (hasBoth || !thousandsPattern.test(raw))) {
      const integerPart = raw.slice(0, lastSep).replace(/[.,]/g, "");
      const fractionPart = raw.slice(lastSep + 1).replace(/[.,]/g, "");
      const parsed = Number(`${integerPart}.${fractionPart}`);
      if (Number.isFinite(parsed)) return Math.max(0, Math.floor(parsed));
    }
  }

  const digits = raw.replace(/[^0-9]/g, "");
  return digits ? Math.max(0, Number.parseInt(digits, 10) || 0) : 0;
}

/* ------------------------------------------------------------------ */
/* Parsing body & normalisasi payload SociaBuzz                        */
/* ------------------------------------------------------------------ */

// JSON dulu, lalu x-www-form-urlencoded. null kalau dua-duanya gagal.
function parseBodyText(text) {
  const t = String(text ?? "");
  if (!t.trim()) return {};

  try {
    return JSON.parse(t);
  } catch {
    // lanjut ke form
  }

  if (t.includes("=")) {
    try {
      const body = {};
      let count = 0;
      for (const [k, v] of new URLSearchParams(t).entries()) {
        if (!k) continue;
        body[k] = v;
        count++;
      }
      if (count > 0) return body;
    } catch {
      // abaikan
    }
  }
  return null;
}

// Baca body request apa pun tipenya. Tidak pernah melempar error.
async function readBody(request) {
  const ct = (request.headers.get("content-type") || "").toLowerCase();

  try {
    if (ct.includes("multipart/form-data")) {
      const fd = await request.formData();
      const body = {};
      for (const [k, v] of fd.entries()) body[k] = typeof v === "string" ? v : "[file]";
      return { text: JSON.stringify(body), body };
    }
    const text = await request.text();
    return { text, body: parseBodyText(text) };
  } catch {
    return { text: "", body: null };
  }
}

function tryParseJsonString(value) {
  if (typeof value !== "string") return value;
  const t = value.trim();
  if ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"))) {
    try {
      return JSON.parse(t);
    } catch {
      // bukan JSON
    }
  }
  return value;
}

// Kumpulkan semua object bersarang (dan JSON-di-dalam-string) sampai beberapa level.
function candidates(body) {
  const out = [];
  const visited = new Set();

  function walk(value, depth) {
    if (!isObj(value) || depth > 5 || visited.has(value)) return;
    visited.add(value);
    if (!Array.isArray(value)) out.push(value);

    for (let child of Object.values(value)) {
      child = tryParseJsonString(child);
      if (isObj(child)) walk(child, depth + 1);
    }
  }

  walk(body, 0);
  return out;
}

const normKey = (k) => String(k).toLowerCase().replace(/[^a-z0-9]/g, "");

// Index key ter-normalisasi (transaction_id == transactionId == TransactionID).
function buildIndex(objects) {
  return objects.map((obj) => {
    const m = new Map();
    for (const [k, v] of Object.entries(obj)) {
      const nk = normKey(k);
      if (!m.has(nk)) m.set(nk, v);
    }
    return m;
  });
}

// Urutan key = prioritas (paling spesifik dulu). Hanya nilai scalar yang dipakai.
function pick(index, keys) {
  for (const key of keys) {
    const nk = normKey(key);
    for (const m of index) {
      const v = m.get(nk);
      if (v !== undefined && v !== null && v !== "" && typeof v !== "object") return v;
    }
  }
  return undefined;
}

const KEYS = {
  idSpecific: [
    "transaction_id", "trx_id", "reference_id", "order_id", "payment_id",
    "invoice_id", "donation_id", "support_id", "reference", "invoice", "uuid",
  ],
  idGeneric: ["id"],
  name: [
    "supporter_name", "donor_name", "donator_name", "sender_name", "customer_name",
    "payer_name", "display_name", "from_name", "nickname", "supporter", "donor",
    "name", "from",
  ],
  amount: [
    "amount", "nominal", "total_amount", "support_amount", "gross_amount",
    "amount_settled", "net_amount", "total", "nominal_price", "price", "value",
  ],
  unitCount: ["unit_count", "qty", "quantity"],
  unitPrice: ["unit_price", "nominal_price"],
  message: ["support_message", "message", "note", "comment", "text"],
  currency: ["currency", "currency_code", "support_currency"],
  created: ["created_at", "paid_at", "timestamp", "time", "date", "support_created_at"],
};

function parseTime(raw) {
  if (raw === undefined || raw === null || raw === "") return Date.now();
  const s = String(raw).trim();
  if (/^\d{13}$/.test(s)) return Number(s);
  if (/^\d{10}$/.test(s)) return Number(s) * 1000;
  const parsed = Date.parse(s);
  return Number.isFinite(parsed) ? parsed : Date.now();
}

async function normalizeSociaBuzz(rawText, body) {
  const index = buildIndex(candidates(body));
  const hash = await sha256Hex(rawText);

  // ID: pakai id transaksi yang spesifik. Kalau hanya ada "id" generik (bisa jadi id akun/halaman
  // yang sama untuk semua donasi) gabungkan dengan hash payload supaya TIDAK pernah bentrok.
  const specific = pick(index, KEYS.idSpecific);
  const generic = pick(index, KEYS.idGeneric);
  let idBase;
  if (specific !== undefined) {
    idBase = cleanText(specific, hash.slice(0, 32), 120);
  } else if (generic !== undefined) {
    idBase = `${cleanText(generic, "x", 80)}_${hash.slice(0, 12)}`;
  } else {
    idBase = hash.slice(0, 48);
  }

  const username = cleanText(pick(index, KEYS.name), "Anonymous", 60);

  let amount = parseAmount(pick(index, KEYS.amount));
  if (amount <= 0) {
    const count = parseAmount(pick(index, KEYS.unitCount));
    const price = parseAmount(pick(index, KEYS.unitPrice));
    if (count > 0 && price > 0) amount = count * price;
  }

  const message = cleanText(pick(index, KEYS.message), "", 500);
  const currency = cleanText(pick(index, KEYS.currency), "IDR", 8).toUpperCase();
  const createdAt = parseTime(pick(index, KEYS.created));

  return {
    id: `sb_${idBase}`,
    source: "sociabuzz",
    username,
    amount,
    message,
    currency,
    createdAt,
    createdAtIso: new Date(createdAt).toISOString(),
    rawHash: hash,
  };
}

/* ------------------------------------------------------------------ */
/* Auth                                                                */
/* ------------------------------------------------------------------ */

function apiKeyOk(request, env) {
  return safeEqual(request.headers.get("x-api-key") || "", env.ROBLOX_API_KEY || "");
}

function adminKeyOk(request, env) {
  const url = new URL(request.url);
  const given = request.headers.get("x-admin-key") || url.searchParams.get("key") || "";
  return safeEqual(given, env.ADMIN_KEY || "");
}

// Key webhook boleh lewat: path /webhook/sociabuzz/<key>, ?key= / ?token=,
// header x-webhook-key / x-webhook-token, atau Authorization: Bearer.
function getWebhookKey(request, url, pathKey) {
  const auth = request.headers.get("authorization") || "";
  return (
    pathKey ||
    url.searchParams.get("key") ||
    url.searchParams.get("token") ||
    request.headers.get("x-webhook-key") ||
    request.headers.get("x-webhook-token") ||
    (auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "") ||
    ""
  );
}

/* ------------------------------------------------------------------ */
/* Log webhook ke D1 (supaya terlihat apa yang SociaBuzz kirim)        */
/* ------------------------------------------------------------------ */

let logTableReady = null;

function ensureLogTable(env) {
  if (!logTableReady) {
    logTableReady = env.DB.batch([
      env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS webhook_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          method TEXT,
          path TEXT,
          status TEXT,
          http_status INTEGER,
          donation_id TEXT,
          ip TEXT,
          content_type TEXT,
          headers TEXT,
          body TEXT,
          note TEXT
        )
      `),
      env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_webhook_log_ts ON webhook_log(ts)`),
    ]).catch((error) => {
      logTableReady = null;
      console.error("[ensureLogTable failed]", error?.message || error);
    });
  }
  return logTableReady;
}

async function logHit(env, request, info) {
  try {
    await ensureLogTable(env);
    const url = new URL(request.url);

    const headers = {};
    for (const [k, v] of request.headers.entries()) {
      headers[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? "[redacted]" : v.slice(0, 200);
    }

    await env.DB.prepare(`
      INSERT INTO webhook_log
        (ts, method, path, status, http_status, donation_id, ip, content_type, headers, body, note)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      Date.now(),
      request.method,
      url.pathname.startsWith(WEBHOOK_BASE + "/") ? WEBHOOK_BASE + "/[key]" : url.pathname,
      info.status || "",
      info.httpStatus ?? null,
      info.donationId || null,
      request.headers.get("cf-connecting-ip") || "",
      request.headers.get("content-type") || "",
      JSON.stringify(headers),
      String(info.body || "").slice(0, LOG_BODY_MAX),
      info.note || null,
    ).run();

    if (Math.random() < 0.05) {
      await env.DB.prepare(`
        DELETE FROM webhook_log
        WHERE id NOT IN (SELECT id FROM webhook_log ORDER BY id DESC LIMIT ?)
      `).bind(LOG_KEEP_ROWS).run();
    }
  } catch (error) {
    console.error("[logHit failed]", error?.message || error);
  }
}

/* ------------------------------------------------------------------ */
/* Webhook                                                             */
/* ------------------------------------------------------------------ */

// Dipakai webhook asli dan /admin/replay.
async function processPayload(env, text, body) {
  if (!isObj(body)) {
    return { http: 400, status: "invalid_body", payload: { ok: false, error: "invalid_json" } };
  }

  if (String(env.DEBUG_WEBHOOK || "") === "1") {
    console.log("[SociaBuzz webhook DEBUG]", String(text).slice(0, 8000));
  }

  const donation = await normalizeSociaBuzz(text, body);
  if (donation.amount <= 0) {
    console.log("[SociaBuzz webhook] amount could not be parsed", donation);
    return {
      http: 422,
      status: "invalid_amount",
      donationId: donation.id,
      payload: { ok: false, error: "invalid_amount", parsed: donation },
    };
  }

  const result = await env.DB.prepare(`
    INSERT OR IGNORE INTO donations
      (id, source, username, amount, message, currency, created_at, created_at_iso, raw_hash, state, attempts)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 0)
  `).bind(
    donation.id,
    donation.source,
    donation.username,
    donation.amount,
    donation.message,
    donation.currency,
    donation.createdAt,
    donation.createdAtIso,
    donation.rawHash,
  ).run();

  const inserted = Number(result?.meta?.changes || 0) > 0;
  return {
    http: 200,
    status: inserted ? "queued" : "duplicate",
    donationId: donation.id,
    note: `${donation.username} ${donation.amount} ${donation.currency}`,
    payload: { ok: true, queued: inserted, duplicate: !inserted, id: donation.id },
  };
}

async function handleWebhook(request, env, ctx, pathKey = "") {
  const url = new URL(request.url);
  const given = getWebhookKey(request, url, pathKey);
  const keyNote = given ? "key=present" : "key=MISSING";
  const { text, body } = await readBody(request);

  if (!safeEqual(given, env.WEBHOOK_KEY || "")) {
    ctx.waitUntil(logHit(env, request, {
      status: "unauthorized", httpStatus: 401, note: keyNote, body: text,
    }));
    return json({ ok: false, error: "unauthorized_webhook" }, 401);
  }

  let outcome;
  try {
    outcome = await processPayload(env, text, body);
  } catch (error) {
    console.error("[webhook error]", error?.stack || error);
    outcome = {
      http: 500,
      status: "error",
      note: String(error?.message || error).slice(0, 300),
      payload: { ok: false, error: "internal_error" },
    };
  }

  ctx.waitUntil(logHit(env, request, {
    status: outcome.status,
    httpStatus: outcome.http,
    donationId: outcome.donationId,
    note: [keyNote, outcome.note].filter(Boolean).join(" | "),
    body: text,
  }));

  return json(outcome.payload, outcome.http);
}

/* ------------------------------------------------------------------ */
/* API untuk Roblox                                                    */
/* ------------------------------------------------------------------ */

async function handlePull(request, env) {
  if (!apiKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  const { body } = await readBody(request);
  if (!isObj(body)) return json({ ok: false, error: "invalid_json" }, 400);

  const serverId = cleanText(body.serverId, "unknown-server", 120);
  const limit = clampInt(body.limit, 1, 20, 5);
  const now = Date.now();
  const leaseUntil = now + LEASE_MS;
  const leaseToken = crypto.randomUUID();

  // Tandai yang sudah kehabisan percobaan (hanya yang tidak sedang di-lease aktif).
  await env.DB.prepare(`
    UPDATE donations
    SET state = 'dead', lease_token = NULL, lease_until = NULL, leased_by = NULL
    WHERE state NOT IN ('done', 'dead')
      AND attempts >= ?
      AND (state = 'queued' OR COALESCE(lease_until, 0) < ?)
  `).bind(MAX_ATTEMPTS, now).run();

  const leased = await env.DB.prepare(`
    UPDATE donations
    SET state = 'leased',
        lease_token = ?,
        lease_until = ?,
        leased_by = ?,
        attempts = attempts + 1
    WHERE id IN (
      SELECT id
      FROM donations
      WHERE attempts < ?
        AND (
          state = 'queued'
          OR (state = 'leased' AND COALESCE(lease_until, 0) < ?)
        )
      ORDER BY created_at ASC
      LIMIT ?
    )
    RETURNING id, source, username, amount, message, currency, created_at_iso, lease_token
  `).bind(leaseToken, leaseUntil, serverId, MAX_ATTEMPTS, now, limit).all();

  const items = (leased.results || []).map((row) => ({
    id: row.id,
    source: row.source,
    username: row.username,
    amount: Number(row.amount) || 0,
    message: row.message || "",
    currency: row.currency || "IDR",
    createdAt: row.created_at_iso,
    leaseToken: row.lease_token,
  }));

  return json({ ok: true, items, serverTime: new Date(now).toISOString() });
}

async function handleAck(request, env) {
  if (!apiKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  const { body } = await readBody(request);
  if (!isObj(body) || !Array.isArray(body.items)) {
    return json({ ok: false, error: "invalid_items" }, 400);
  }

  const now = Date.now();
  const statements = [];

  for (const item of body.items.slice(0, 50)) {
    const id = cleanText(item?.id, "", 160);
    const leaseToken = cleanText(item?.leaseToken, "", 120);
    const status = String(item?.status || "failed");
    if (!id) continue;

    if (status === "done") {
      // Donasi sudah terkirim ke game. Tandai done walau lease sudah kedaluwarsa/berpindah,
      // supaya tidak terkirim dobel.
      statements.push(env.DB.prepare(`
        UPDATE donations
        SET state = 'done', done_at = ?, lease_token = NULL, lease_until = NULL, leased_by = NULL
        WHERE id = ? AND state != 'done'
      `).bind(now, id));
    } else if (leaseToken) {
      statements.push(env.DB.prepare(`
        UPDATE donations
        SET state = CASE WHEN attempts >= ? THEN 'dead' ELSE 'queued' END,
            lease_token = NULL,
            lease_until = NULL,
            leased_by = NULL
        WHERE id = ? AND lease_token = ?
      `).bind(MAX_ATTEMPTS, id, leaseToken));
    }
  }

  if (statements.length) await env.DB.batch(statements);
  return json({ ok: true, acknowledged: statements.length });
}

async function handleTop(request, env) {
  if (!apiKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  const url = new URL(request.url);
  const limit = clampInt(url.searchParams.get("limit"), 1, 25, 10);

  const data = await env.DB.prepare(`
    SELECT username, SUM(amount) AS total_amount, COUNT(*) AS donation_count
    FROM donations
    WHERE amount > 0 AND source = 'sociabuzz'
    GROUP BY username
    ORDER BY total_amount DESC, donation_count DESC
    LIMIT ?
  `).bind(limit).all();

  return json({
    ok: true,
    items: (data.results || []).map((row, i) => ({
      rank: i + 1,
      username: row.username,
      amount: Number(row.total_amount) || 0,
      count: Number(row.donation_count) || 0,
    })),
  });
}

/* ------------------------------------------------------------------ */
/* Admin                                                               */
/* ------------------------------------------------------------------ */

async function handleAdminStatus(request, env) {
  if (!adminKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  await ensureLogTable(env);

  const counts = await env.DB.prepare(`
    SELECT state, COUNT(*) AS count FROM donations GROUP BY state
  `).all();

  const latest = await env.DB.prepare(`
    SELECT id, source, username, amount, currency, created_at_iso, state, attempts
    FROM donations
    ORDER BY created_at DESC
    LIMIT 10
  `).all();

  const lastHits = await env.DB.prepare(`
    SELECT id, ts, method, status, http_status, donation_id, note
    FROM webhook_log
    ORDER BY id DESC
    LIMIT 5
  `).all();

  return json({
    ok: true,
    counts: counts.results || [],
    latest: latest.results || [],
    lastWebhookHits: (lastHits.results || []).map((r) => ({ ...r, ts: new Date(r.ts).toISOString() })),
  });
}

// Lihat request apa saja yang masuk ke webhook (termasuk yang ditolak).
async function handleAdminLogs(request, env) {
  if (!adminKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  await ensureLogTable(env);

  const url = new URL(request.url);
  const limit = clampInt(url.searchParams.get("limit"), 1, 100, 20);
  const full = url.searchParams.get("full") === "1";

  const rows = await env.DB.prepare(`
    SELECT id, ts, method, path, status, http_status, donation_id, ip, content_type, headers, body, note
    FROM webhook_log
    ORDER BY id DESC
    LIMIT ?
  `).bind(limit).all();

  const items = (rows.results || []).map((r) => {
    let headers = r.headers;
    try {
      headers = JSON.parse(r.headers);
    } catch {
      // biarkan string
    }
    return {
      ...r,
      ts: new Date(r.ts).toISOString(),
      headers,
      body: full ? r.body : String(r.body || "").slice(0, 1500),
    };
  });

  return json({ ok: true, items });
}

// Proses ulang payload dari log (berguna kalau parser sudah diperbaiki).
async function handleAdminReplay(request, env) {
  if (!adminKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  const { body } = await readBody(request);
  const logId = clampInt(body?.logId, 1, Number.MAX_SAFE_INTEGER, 0);
  if (!logId) return json({ ok: false, error: "logId_required" }, 400);

  await ensureLogTable(env);
  const row = await env.DB.prepare(`SELECT body FROM webhook_log WHERE id = ?`).bind(logId).first();
  if (!row) return json({ ok: false, error: "log_not_found" }, 404);

  const outcome = await processPayload(env, row.body, parseBodyText(row.body));
  return json({ replayedLogId: logId, ...outcome.payload });
}

// Uji parser dengan payload asli TANPA menyimpan ke database.
async function handleAdminParse(request, env) {
  if (!adminKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  const { text, body } = await readBody(request);
  if (!isObj(body)) return json({ ok: false, error: "invalid_json" }, 400);
  return json({ ok: true, parsed: await normalizeSociaBuzz(text, body) });
}

async function handleAdminTest(request, env) {
  if (!adminKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  const { body } = await readBody(request);
  if (!isObj(body)) return json({ ok: false, error: "invalid_json" }, 400);

  const amount = Math.max(1, parseAmount(body.amount || 5000));
  const username = cleanText(body.username, "TestUser", 60);
  const message = cleanText(body.message, "Test SociaBuzz -> Roblox", 500);
  const id = `test_${crypto.randomUUID()}`;
  const now = Date.now();

  await env.DB.prepare(`
    INSERT INTO donations
      (id, source, username, amount, message, currency, created_at, created_at_iso, raw_hash, state, attempts)
    VALUES (?, 'test', ?, ?, ?, 'IDR', ?, ?, ?, 'queued', 0)
  `).bind(id, username, amount, message, now, new Date(now).toISOString(), id).run();

  return json({ ok: true, id });
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const { pathname } = url;
      const method = request.method;

      if (method === "GET" && pathname === "/") {
        return json({
          ok: true,
          service: "SociaBuzz -> Roblox Bridge",
          version: 2,
          endpoints: [WEBHOOK_BASE, "/api/pull", "/api/ack", "/api/top"],
        });
      }

      // Webhook (boleh juga dengan key di path: /webhook/sociabuzz/<key>)
      if (pathname === WEBHOOK_BASE || pathname.startsWith(WEBHOOK_BASE + "/")) {
        const pathKey = pathname.length > WEBHOOK_BASE.length + 1
          ? safeDecode(pathname.slice(WEBHOOK_BASE.length + 1))
          : "";

        if (method === "POST" || method === "PUT" || method === "PATCH") {
          return await handleWebhook(request, env, ctx, pathKey);
        }

        // Beberapa penyedia memvalidasi URL dengan GET/HEAD/OPTIONS. Jawab 200 dan catat.
        if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
          ctx.waitUntil(logHit(env, request, { status: "probe", httpStatus: 200 }));
          return json({ ok: true, hint: "send POST to this URL" });
        }
      }

      if (method === "POST" && pathname === "/api/pull") return await handlePull(request, env);
      if (method === "POST" && pathname === "/api/ack") return await handleAck(request, env);
      if (method === "GET" && pathname === "/api/top") return await handleTop(request, env);

      if (method === "GET" && pathname === "/admin/status") return await handleAdminStatus(request, env);
      if (method === "GET" && pathname === "/admin/logs") return await handleAdminLogs(request, env);
      if (method === "POST" && pathname === "/admin/replay") return await handleAdminReplay(request, env);
      if (method === "POST" && pathname === "/admin/parse") return await handleAdminParse(request, env);
      if (method === "POST" && pathname === "/admin/test") return await handleAdminTest(request, env);

      return json({ ok: false, error: "not_found" }, 404);
    } catch (error) {
      console.error("[Worker error]", error?.stack || error);
      return json({ ok: false, error: "internal_error" }, 500);
    }
  },
};
