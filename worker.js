const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
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

  // Handle decimal forms such as 10000.00 or 10.000,00.
  // A single separator followed by exactly 3 digits is treated as a thousands separator.
  if (lastSep >= 0) {
    const fractionLength = raw.length - lastSep - 1;
    const hasBoth = lastDot >= 0 && lastComma >= 0;
    const singleThousandsPattern = /^-?\d{1,3}([.,]\d{3})+$/;

    if (fractionLength > 0 && fractionLength <= 2 && (hasBoth || !singleThousandsPattern.test(raw))) {
      const integerPart = raw.slice(0, lastSep).replace(/[.,]/g, "");
      const fractionPart = raw.slice(lastSep + 1).replace(/[.,]/g, "");
      const parsed = Number(`${integerPart}.${fractionPart}`);
      if (Number.isFinite(parsed)) return Math.max(0, Math.floor(parsed));
    }
  }

  const digits = raw.replace(/[^0-9]/g, "");
  return digits ? Math.max(0, Number.parseInt(digits, 10) || 0) : 0;
}

function candidates(body) {
  // SociaBuzz may wrap webhook fields in a nested object. Walk a few levels
  // so the bridge does not depend on one exact wrapper name.
  const out = [];
  const visited = new Set();

  function walk(value, depth) {
    if (!value || typeof value !== "object" || depth > 4 || visited.has(value)) return;
    visited.add(value);

    if (!Array.isArray(value)) out.push(value);

    for (const child of Object.values(value)) {
      if (child && typeof child === "object") walk(child, depth + 1);
    }
  }

  walk(body, 0);
  return out;
}

function firstValue(objects, keys) {
  for (const obj of objects) {
    for (const key of keys) {
      if (obj[key] !== undefined && obj[key] !== null && obj[key] !== "") {
        return obj[key];
      }
    }
  }
  return undefined;
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function normalizeSociaBuzz(rawText, body) {
  const list = candidates(body);

  const externalId = firstValue(list, [
    "transaction_id", "transactionId", "trx_id", "trxId", "reference_id",
    "referenceId", "order_id", "orderId", "payment_id", "paymentId", "id",
  ]);

  const username = cleanText(firstValue(list, [
    "supporter_name", "supporterName", "donor_name", "donorName", "donator_name",
    "donatorName", "sender_name", "senderName", "customer_name", "customerName",
    "payer_name", "payerName", "name", "from",
  ]), "Anonymous", 60);

  let amount = parseAmount(firstValue(list, [
    "amount", "nominal", "total", "total_amount", "totalAmount", "support_amount",
    "supportAmount", "gross_amount", "grossAmount", "nominal_price", "nominalPrice",
    "price", "value",
  ]));

  if (amount <= 0) {
    const unitCount = parseAmount(firstValue(list, ["unit_count", "unitCount", "qty", "quantity"]));
    const unitPrice = parseAmount(firstValue(list, ["unit_price", "unitPrice", "nominal_price", "nominalPrice"]));
    if (unitCount > 0 && unitPrice > 0) amount = unitCount * unitPrice;
  }

  const message = cleanText(firstValue(list, [
    "support_message", "supportMessage", "message", "note", "comment", "text",
  ]), "", 500);

  const currency = cleanText(firstValue(list, [
    "currency", "currency_code", "currencyCode", "support_currency", "supportCurrency",
  ]), "IDR", 8).toUpperCase();
  const createdRaw = firstValue(list, [
    "created_at", "createdAt", "paid_at", "paidAt", "timestamp", "time", "date",
    "support_created_at", "supportCreatedAt",
  ]);

  let createdAt = Date.now();
  if (createdRaw) {
    const parsed = Date.parse(String(createdRaw));
    if (Number.isFinite(parsed)) createdAt = parsed;
  }

  const hash = await sha256Hex(rawText);
  const idBase = externalId ? cleanText(externalId, hash.slice(0, 32), 120) : hash.slice(0, 48);

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

function apiKeyOk(request, env) {
  const given = request.headers.get("x-api-key") || "";
  return Boolean(env.ROBLOX_API_KEY) && given === env.ROBLOX_API_KEY;
}

function adminKeyOk(request, env) {
  const url = new URL(request.url);
  const given = request.headers.get("x-admin-key") || url.searchParams.get("key") || "";
  return Boolean(env.ADMIN_KEY) && given === env.ADMIN_KEY;
}

async function readJson(request) {
  const text = await request.text();
  if (!text) return { text: "{}", body: {} };

  try {
    return { text, body: JSON.parse(text) };
  } catch {
    // Fallback for providers that POST application/x-www-form-urlencoded.
    try {
      const params = new URLSearchParams(text);
      const body = {};
      let count = 0;
      for (const [key, value] of params.entries()) {
        body[key] = value;
        count++;
      }
      if (count > 0) return { text, body };
    } catch {
      // ignore
    }
    return { text, body: null };
  }
}

async function handleWebhook(request, env) {
  const url = new URL(request.url);
  const key = url.searchParams.get("key") || request.headers.get("x-webhook-key") || "";
  if (!env.WEBHOOK_KEY || key !== env.WEBHOOK_KEY) {
    return json({ ok: false, error: "unauthorized_webhook" }, 401);
  }

  const { text, body } = await readJson(request);
  if (!body || typeof body !== "object") {
    return json({ ok: false, error: "invalid_json" }, 400);
  }

  if (String(env.DEBUG_WEBHOOK || "") === "1") {
    console.log("[SociaBuzz webhook DEBUG]", text.slice(0, 8000));
  }

  const donation = await normalizeSociaBuzz(text, body);
  if (donation.amount <= 0) {
    console.log("[SociaBuzz webhook] amount could not be parsed", donation);
    return json({ ok: false, error: "invalid_amount", parsed: donation }, 422);
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
  return json({
    ok: true,
    queued: inserted,
    duplicate: !inserted,
    id: donation.id,
  });
}

async function handlePull(request, env) {
  if (!apiKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  const { body } = await readJson(request);
  if (!body || typeof body !== "object") return json({ ok: false, error: "invalid_json" }, 400);

  const serverId = cleanText(body.serverId, "unknown-server", 120);
  const limit = clampInt(body.limit, 1, 20, 5);
  const now = Date.now();
  const leaseUntil = now + 45_000;
  const leaseToken = crypto.randomUUID();

  // Mark exhausted rows as dead before leasing new work.
  await env.DB.prepare(`
    UPDATE donations
    SET state = 'dead', lease_token = NULL, lease_until = NULL, leased_by = NULL
    WHERE state != 'done' AND attempts >= 8
  `).run();

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
      WHERE attempts < 8
        AND (
          state = 'queued'
          OR (state = 'leased' AND COALESCE(lease_until, 0) < ?)
        )
      ORDER BY created_at ASC
      LIMIT ?
    )
    RETURNING id, source, username, amount, message, currency, created_at_iso, lease_token
  `).bind(leaseToken, leaseUntil, serverId, now, limit).all();

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
  const { body } = await readJson(request);
  if (!body || !Array.isArray(body.items)) return json({ ok: false, error: "invalid_items" }, 400);

  const now = Date.now();
  const statements = [];

  for (const item of body.items.slice(0, 50)) {
    const id = cleanText(item?.id, "", 160);
    const leaseToken = cleanText(item?.leaseToken, "", 120);
    const status = String(item?.status || "failed");
    if (!id || !leaseToken) continue;

    if (status === "done") {
      statements.push(env.DB.prepare(`
        UPDATE donations
        SET state = 'done', done_at = ?, lease_token = NULL, lease_until = NULL, leased_by = NULL
        WHERE id = ? AND lease_token = ?
      `).bind(now, id, leaseToken));
    } else {
      statements.push(env.DB.prepare(`
        UPDATE donations
        SET state = CASE WHEN attempts >= 8 THEN 'dead' ELSE 'queued' END,
            lease_token = NULL,
            lease_until = NULL,
            leased_by = NULL
        WHERE id = ? AND lease_token = ?
      `).bind(id, leaseToken));
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
    items: (data.results || []).map((row, index) => ({
      rank: index + 1,
      username: row.username,
      amount: Number(row.total_amount) || 0,
      count: Number(row.donation_count) || 0,
    })),
  });
}

async function handleAdminStatus(request, env) {
  if (!adminKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);

  const counts = await env.DB.prepare(`
    SELECT state, COUNT(*) AS count
    FROM donations
    GROUP BY state
  `).all();

  const latest = await env.DB.prepare(`
    SELECT id, username, amount, currency, created_at_iso, state, attempts
    FROM donations
    ORDER BY created_at DESC
    LIMIT 10
  `).all();

  return json({ ok: true, counts: counts.results || [], latest: latest.results || [] });
}

async function handleAdminTest(request, env) {
  if (!adminKeyOk(request, env)) return json({ ok: false, error: "unauthorized" }, 401);
  const { body } = await readJson(request);
  if (!body || typeof body !== "object") return json({ ok: false, error: "invalid_json" }, 400);

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

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (request.method === "GET" && url.pathname === "/") {
        return json({
          ok: true,
          service: "SociaBuzz -> Roblox Bridge",
          version: 1,
          endpoints: ["/webhook/sociabuzz", "/api/pull", "/api/ack", "/api/top"],
        });
      }

      if (request.method === "POST" && url.pathname === "/webhook/sociabuzz") {
        return await handleWebhook(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/pull") {
        return await handlePull(request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/ack") {
        return await handleAck(request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/top") {
        return await handleTop(request, env);
      }
      if (request.method === "GET" && url.pathname === "/admin/status") {
        return await handleAdminStatus(request, env);
      }
      if (request.method === "POST" && url.pathname === "/admin/test") {
        return await handleAdminTest(request, env);
      }

      return json({ ok: false, error: "not_found" }, 404);
    } catch (error) {
      console.error("[Worker error]", error?.stack || error);
      return json({ ok: false, error: "internal_error" }, 500);
    }
  },
};
