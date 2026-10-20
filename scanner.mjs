// FOMO Coin Scanner — cloud version (GitHub Actions, every 5 min) → Telegram alerts
// Alerts only: no buying, no wallet, no keys.
// Token and chat ID come from GitHub Secrets (never paste them in this file).

import fs from "node:fs";

// ======= SETTINGS =======
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

const CHAINS          = ["solana", "base"];

// Momentum filters
const MAX_AGE_MIN     = 30;      // only pairs younger than this
const MIN_LIQ_USD     = 10000;   // skip ultra-thin pools
const MIN_VOL_5M_USD  = 3000;    // real early activity
const MIN_BUYS_5M     = 20;      // buy txns in last 5 min
const MIN_BUY_SELL    = 1.2;     // buys must outnumber sells by this ratio
const MAX_FDV_USD     = 2000000; // keep it early

// Safety filters (hard fails = no alert)
const MIN_LP_LOCKED_PCT  = 80;   // % of liquidity locked or burned
const MAX_DEV_PCT        = 10;   // max % of supply the dev holds
const MAX_TOP10_PCT      = 40;   // max % held by top 10 wallets (pools/lockers excluded)
const MAX_SELL_TAX_PCT   = 10;   // Base only
const MAX_RUGCHECK_SCORE = 50;   // Solana: 0–100, higher = riskier
const SKIP_IF_UNCHECKED  = false;// true = skip coins the safety APIs haven't indexed yet

// Top-picks scoring: only coins scoring this or higher (0–100) get sent.
// Raise it for fewer, pickier alerts; lower it for more.
const MIN_SCORE          = 70;
// ========================

if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
  console.error("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID secret.");
  process.exit(1);
}

const API = "https://api.dexscreener.com";
const SEEN_FILE = "seen.json";

function loadSeen() {
  try { return JSON.parse(fs.readFileSync(SEEN_FILE, "utf8")) || {}; } catch { return {}; }
}
function saveSeen(seen) {
  const cutoff = Date.now() - 24 * 3600 * 1000;
  for (const k in seen) if (seen[k] < cutoff) delete seen[k];
  fs.writeFileSync(SEEN_FILE, JSON.stringify(seen));
}

async function getJSON(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(20000), headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return res.json();
}

async function sendTelegram(text) {
  const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text, parse_mode: "HTML", disable_web_page_preview: true })
  });
  const data = await res.json().catch(() => ({}));
  if (!data.ok) console.error("Telegram error:", JSON.stringify(data));
  return data.ok;
}

const fmt = n => n >= 1e6 ? `$${(n/1e6).toFixed(2)}M` : n >= 1e3 ? `$${(n/1e3).toFixed(1)}K` : `$${Math.round(n||0)}`;
const pct = n => (n == null || isNaN(n)) ? "?" : `${n.toFixed(1)}%`;
const esc = s => String(s || "").replace(/[<>&]/g, c => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));

// ---------- Safety checks ----------
async function checkSolana(mint) {
  const out = { checked: false, fails: [], warns: [], lpLocked: null, devPct: null, top10Pct: null, extra: "" };
  let r;
  try { r = await getJSON(`https://api.rugcheck.xyz/v1/tokens/${mint}/report`); } catch { return out; }
  if (!r || r.error) return out;
  out.checked = true;

  if (r.rugged) out.fails.push("Already flagged as rugged");
  const mintAuth   = r.mintAuthority   ?? r.token?.mintAuthority;
  const freezeAuth = r.freezeAuthority ?? r.token?.freezeAuthority;
  if (mintAuth)   out.fails.push("Mint authority active");
  if (freezeAuth) out.fails.push("Freeze authority active");

  const lpVals = (r.markets || []).map(m => m?.lp?.lpLockedPct).filter(v => typeof v === "number");
  if (lpVals.length) out.lpLocked = Math.max(...lpVals);
  else if (typeof r.lpLockedPct === "number") out.lpLocked = r.lpLockedPct;

  const known = r.knownAccounts || {};
  const holders = (r.topHolders || []).filter(h => !known[h.owner] && !known[h.address]);
  out.top10Pct = holders.slice(0, 10).reduce((s, h) => s + (h.pct || 0), 0);
  const insiderPct = holders.filter(h => h.insider).reduce((s, h) => s + (h.pct || 0), 0);

  const dec = r.token?.decimals;
  const supply = r.token?.supply && dec != null ? r.token.supply / 10 ** dec : null;
  if (r.creatorBalance != null && supply) out.devPct = (r.creatorBalance / 10 ** dec) / supply * 100;
  if (out.devPct != null && out.devPct > 100) out.devPct = null;

  const score = r.score_normalised;
  if (typeof score === "number" && score > MAX_RUGCHECK_SCORE) out.fails.push(`RugCheck risk score ${score}/100`);
  for (const risk of r.risks || []) if (risk.level === "danger") out.warns.push(risk.name);
  if (insiderPct > 15) out.warns.push(`Insider wallets hold ${pct(insiderPct)}`);
  out.extra = typeof score === "number" ? `RugCheck score: ${score}/100` : "";
  return out;
}

async function checkBase(addr) {
  const out = { checked: false, fails: [], warns: [], lpLocked: null, devPct: null, top10Pct: null, extra: "" };
  let res;
  try { res = await getJSON(`https://api.gopluslabs.io/api/v1/token_security/8453?contract_addresses=${addr}`); } catch { return out; }
  const d = res?.result?.[addr.toLowerCase()];
  if (!d) return out;
  out.checked = true;

  const yes = v => v === "1" || v === 1;
  if (yes(d.is_honeypot))          out.fails.push("Honeypot");
  if (yes(d.cannot_sell_all))      out.fails.push("Can't sell all");
  if (yes(d.is_mintable))          out.fails.push("Mintable");
  if (yes(d.owner_change_balance)) out.fails.push("Owner can change balances");
  if (yes(d.hidden_owner))         out.fails.push("Hidden owner");
  if (yes(d.transfer_pausable))    out.fails.push("Trading can be paused");
  if (yes(d.honeypot_with_same_creator)) out.fails.push("Creator made honeypots before");
  if (yes(d.is_blacklisted))       out.warns.push("Has blacklist function");
  if (d.is_open_source === "0")    out.warns.push("Contract not verified");

  const buyTax  = parseFloat(d.buy_tax  || "0") * 100;
  const sellTax = parseFloat(d.sell_tax || "0") * 100;
  if (sellTax > MAX_SELL_TAX_PCT) out.fails.push(`Sell tax ${pct(sellTax)}`);

  const DEAD = /^0x0{40}$|^0x0{36}dead$/i;
  if (Array.isArray(d.lp_holders) && d.lp_holders.length) {
    out.lpLocked = d.lp_holders
      .filter(h => yes(h.is_locked) || DEAD.test(h.address || ""))
      .reduce((s, h) => s + parseFloat(h.percent || "0"), 0) * 100;
  }
  out.devPct = d.creator_percent != null ? parseFloat(d.creator_percent) * 100 : null;
  if (Array.isArray(d.holders)) {
    out.top10Pct = d.holders
      .filter(h => !yes(h.is_contract) && !yes(h.is_locked) && !DEAD.test(h.address || ""))
      .slice(0, 10)
      .reduce((s, h) => s + parseFloat(h.percent || "0"), 0) * 100;
  }
  out.extra = `Tax: buy ${pct(buyTax)} / sell ${pct(sellTax)}`;
  return out;
}

function applyThresholds(s) {
  if (s.lpLocked != null && s.lpLocked < MIN_LP_LOCKED_PCT) s.fails.push(`Only ${pct(s.lpLocked)} LP locked`);
  if (s.devPct   != null && s.devPct   > MAX_DEV_PCT)       s.fails.push(`Dev holds ${pct(s.devPct)}`);
  if (s.top10Pct != null && s.top10Pct > MAX_TOP10_PCT)     s.fails.push(`Top 10 hold ${pct(s.top10Pct)}`);
  return s;
}

// ---------- Scoring (0–100) ----------
// Higher = better-looking setup. NOT a prediction; most new coins still fail.
const lerp = (x, lo, hi, max) => Math.max(0, Math.min(max, ((x - lo) / (hi - lo)) * max));

function scoreCoin(c, s) {
  const p = c.p;
  const parts = {};

  // Buy pressure: buys vs sells in last 5 min (20)
  parts.pressure = lerp(c.ratio, 1.2, 3, 20);

  // Activity: number of buys in last 5 min (15)
  parts.activity = lerp(c.buys5, MIN_BUYS_5M, 150, 15);

  // Accelerating volume: last 5 min vs hourly pace (15)
  const h1 = p.volume?.h1 || 0;
  const accel = h1 > 0 ? (c.vol5 * 12) / h1 : 1;
  parts.accel = lerp(accel, 0.5, 2, 15);

  // Liquidity depth vs market cap: deeper = harder to dump (10)
  const depth = c.fdv ? c.liq / c.fdv : 0.1;
  parts.depth = lerp(depth, 0.05, 0.15, 10);

  // Healthy price action: rising, but not a blow-off spike (10)
  const m5 = p.priceChange?.m5 ?? 0;
  parts.price = m5 < 0 ? 0 : m5 <= 5 ? 5 : m5 <= 60 ? 10 : m5 >= 150 ? 0 : 10 - lerp(m5, 60, 150, 10);

  // Still early: smaller market cap = more room (5)
  parts.early = c.fdv ? 5 - lerp(c.fdv, 300000, MAX_FDV_USD, 5) : 2;

  // Safety (20)
  let safety = s.checked ? 20 : 5;
  if (s.checked) {
    safety -= 5 * s.warns.length;
    if (s.lpLocked != null && s.lpLocked < 99) safety -= 3;
    if (s.devPct   != null && s.devPct   > 3)  safety -= 3;
    if (s.top10Pct != null && s.top10Pct > 25) safety -= 3;
  }
  parts.safety = Math.max(0, safety);

  // Community: website + socials (5)
  const socials = (p.info?.socials || []).map(x => (x.type || "").toLowerCase());
  parts.community = ((p.info?.websites || []).length ? 2 : 0)
    + (socials.some(t => t === "twitter" || t === "x") ? 2 : 0)
    + (socials.includes("telegram") ? 1 : 0);

  const total = Math.round(Object.values(parts).reduce((a, b) => a + b, 0));
  return { total, parts };
}

const bar = n => "🟩".repeat(Math.round(n / 20)) + "⬜".repeat(5 - Math.round(n / 20));

// ---------- Main ----------
const seen = loadSeen();

// Manual test: run the workflow by hand with "test" ticked to get a hello message
if (process.env.SEND_TEST === "true") {
  await sendTelegram("✅ FOMO bot is connected and running in the cloud.");
}

const [profiles, boosts] = await Promise.all([
  getJSON(`${API}/token-profiles/latest/v1`).catch(e => { console.error(e.message); return []; }),
  getJSON(`${API}/token-boosts/latest/v1`).catch(e => { console.error(e.message); return []; })
]);

const byChain = {};
for (const t of [...(profiles || []), ...(boosts || [])]) {
  if (!t || !CHAINS.includes(t.chainId) || !t.tokenAddress) continue;
  if (seen[`${t.chainId}:${t.tokenAddress}`]) continue;
  (byChain[t.chainId] ||= new Set()).add(t.tokenAddress);
}

const candidates = [];
for (const chain in byChain) {
  const addrs = [...byChain[chain]];
  for (let i = 0; i < addrs.length; i += 30) {
    const pairs = await getJSON(`${API}/tokens/v1/${chain}/${addrs.slice(i, i + 30).join(",")}`).catch(() => []);
    const best = {};
    for (const p of pairs || []) {
      const a = p.baseToken?.address;
      if (a && (!best[a] || (p.liquidity?.usd || 0) > (best[a].liquidity?.usd || 0))) best[a] = p;
    }
    for (const a in best) {
      const p = best[a];
      const ageMin = (Date.now() - (p.pairCreatedAt || 0)) / 60000;
      const liq = p.liquidity?.usd || 0, vol5 = p.volume?.m5 || 0;
      const buys5 = p.txns?.m5?.buys || 0, sells5 = p.txns?.m5?.sells || 0;
      const fdv = p.fdv || p.marketCap || 0;
      const ratio = buys5 / Math.max(sells5, 1);
      if (ageMin > MAX_AGE_MIN || liq < MIN_LIQ_USD || vol5 < MIN_VOL_5M_USD) continue;
      if (buys5 < MIN_BUYS_5M || ratio < MIN_BUY_SELL) continue;
      if (fdv && fdv > MAX_FDV_USD) continue;
      candidates.push({ chain, a, p, ageMin, liq, vol5, buys5, sells5, fdv, ratio });
    }
  }
}

let sent = 0, blocked = 0, lowScore = 0;
candidates.sort((x, y) => y.vol5 - x.vol5);
for (const c of candidates) {
  const s = applyThresholds(c.chain === "solana" ? await checkSolana(c.a) : await checkBase(c.a));
  if (!s.checked && SKIP_IF_UNCHECKED) continue;
  if (s.fails.length) { seen[`${c.chain}:${c.a}`] = Date.now(); blocked++; continue; }

  const sc = scoreCoin(c, s);
  console.log(`${c.p.baseToken?.symbol} (${c.chain}) score ${sc.total}`, JSON.stringify(sc.parts));
  // Below the bar: don't mark as seen, so it's re-scored next run if it heats up
  if (sc.total < MIN_SCORE) { lowScore++; continue; }
  seen[`${c.chain}:${c.a}`] = Date.now();

  const p = c.p;
  const socials = (p.info?.socials || []).map(x => `<a href="${x.url}">${esc(x.type)}</a>`).join(" · ");
  const checkLink = c.chain === "solana"
    ? `<a href="https://rugcheck.xyz/tokens/${c.a}">RugCheck</a>`
    : `<a href="https://gopluslabs.io/token-security/8453/${c.a}">GoPlus</a>`;
  const safety = s.checked
    ? `🛡 <b>Safety: passed</b>
🔒 LP locked: ${pct(s.lpLocked)}   👤 Dev: ${pct(s.devPct)}   🐋 Top10: ${pct(s.top10Pct)}${s.extra ? "\n" + s.extra : ""}${s.warns.length ? "\n⚠️ " + s.warns.map(esc).join("; ") : ""}`
    : `⚠️ <b>Safety: NOT CHECKED</b> (too new for scanners — check manually)`;

  const msg =
`🚨 <b>${esc(p.baseToken.name)}</b> ($${esc(p.baseToken.symbol)}) — ${c.chain}
⭐️ <b>Score: ${sc.total}/100</b> ${bar(sc.total)}
⏱ Age: ${Math.round(c.ageMin)} min
💧 Liq: ${fmt(c.liq)}   📊 FDV: ${fmt(c.fdv)}
🔥 5m vol: ${fmt(c.vol5)}   🟢 ${c.buys5} / 🔴 ${c.sells5} (${c.ratio.toFixed(1)}x)
📈 5m change: ${p.priceChange?.m5 ?? 0}%

${safety}

${socials ? "🌐 " + socials + "\n" : ""}📉 <a href="${p.url}">Chart</a> · 🔍 ${checkLink}
<code>${c.a}</code>`;

  if (await sendTelegram(msg)) sent++;
}

saveSeen(seen);
console.log(`Scanned ${Object.values(byChain).reduce((n, s) => n + s.size, 0)} new tokens · ${candidates.length} had momentum · ${blocked} blocked by safety · ${lowScore} scored under ${MIN_SCORE} · ${sent} sent`);
