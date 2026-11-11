// The key tool page (SPEC §18.2), inlined into keytool.html after the library modules. It talks only to hosts the
// user enters ([KT-1]) and gathers the newest log before signing anything ([KT-2]).

const rc = { ...__modules["index.js"] };
for (const name of ["errors.js", "json.js", "encoding.js", "labels.js", "binding.js", "crypto.js", "keys.js", "recovery.js", "id.js", "log.js",
  "vaultcheck.js", "profile.js", "messages.js", "proof.js", "links.js", "file.js", "argon2.js", "vault.js", "account.js", "testing.js"]) {
  Object.assign(rc, __modules[name]);
}
const $ = (id) => document.getElementById(id);
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const now = () => Math.floor(Date.now() / 1000);
let current = null; // { keys, key, log, state, vault, public, realm, username, account }

function show(text, ok = true) {
  $("status").className = ok ? "ok" : "err";
  $("status").textContent = ok ? "Done." : "Failed.";
  $("out").textContent = text;
}

/** Show progress during an action: the status stays "Working…" until the action ends. */
function progress(text) {
  $("out").textContent = text;
}

function explain(e) {
  if (e instanceof rc.RootcardError) {
    const why = {
      wrong_recovery_key: "This recovery key is not the identity's current one.",
      bad_checksum: "The recovery key has a typo.",
      unlock_failed: "Wrong password or recovery key.",
      weak_password: "The password is too weak: at least 12 characters, not the username.",
      fork: "Two versions of the identity's log fork. Extend the branch the primary host holds.",
      not_home: "This host is not the identity's primary host.",
      unsupported_browser: "This browser lacks WebCrypto Ed25519 or X25519.",
    }[e.code];
    return `${why ?? "Error"} (${e.code})`;
  }
  return String(e?.message ?? e);
}

async function run(f) {
  for (const b of document.querySelectorAll("button")) b.disabled = true;
  $("status").className = "busy";
  $("status").textContent = "Working…";
  $("out").textContent = "";
  try {
    await rc.checkSupport();
    show(await f());
  } catch (e) {
    show(explain(e), false);
  } finally {
    for (const b of document.querySelectorAll("button")) b.disabled = false;
    render();
    $("result").scrollIntoView({ block: "nearest" });
  }
}

function download(name, value) {
  const blob = new Blob([rc.canonicalString(value) + "\n"], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}

async function readFile(input) {
  const f = input.files?.[0];
  if (!f) return undefined;
  return rc.parseLimited(new Uint8Array(await f.arrayBuffer()), rc.FILE_LIMIT ?? 5 * 1024 * 1024);
}

function checkUrl(url) {
  if (!/^https:\/\//.test(url) && !/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/.test(url)) throw new Error(`${url}: hosts are reached over https`);
  return url.replace(/\/+$/, "");
}

const LOCAL = /^(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/;

/**
 * A host address as the user typed it, made into a base URL: surrounding space and trailing slashes removed, and
 * `https://` added when no scheme is given (`http://` for this computer). The result is then checked ([HST-22]).
 */
function normalizeHost(text) {
  let t = text.trim().replace(/\/+$/, "");
  if (t && !/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(t)) t = (LOCAL.test(t) ? "http://" : "https://") + t;
  return t;
}

function checkHost(text) {
  const base = normalizeHost(text);
  if (!base) throw new Error("Enter a host address, such as https://id.example.com.");
  try {
    rc.checkBaseUrl(base);
  } catch {
    let why = "use the form https://host, with an optional :port and /path";
    if (/\/[vV][0-9]+$/.test(base)) why = `leave out the /${rc.API_VERSION} at the end: enter the address without it`;
    else if (/^http:\/\//.test(base)) why = "hosts are reached over https:// (plain http:// only on this computer)";
    else if (/[?#]/.test(base)) why = "leave out the ? or # part";
    throw new Error(`"${text.trim()}" is not a host address: ${why}.`);
  }
  return base;
}

// The API root of a host: every endpoint is under `<base URL>/v0` until 1.0.0 (HOST_PROTOCOL.md §1.3). Base URLs
// (`home.url`, and `url` in signed messages) never include the version.
function apiRoot(base) {
  return `${checkHost(base)}/${rc.API_VERSION}`;
}

async function http(method, url, body) {
  let res;
  try {
    res = await fetch(checkUrl(url), {
      method,
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : rc.canonicalString(body),
      credentials: "omit",
      referrerPolicy: "no-referrer",
      cache: "no-store",
    });
  } catch {
    throw new Error(`${url}: the host could not be reached. Check the address and the network connection.`);
  }
  const text = await res.text();
  let value;
  try {
    value = text ? rc.parseJson(text) : true;
  } catch {
    throw new Error(`${url}: HTTP ${res.status}, and the answer is not a rootcard host's. Check the address.`);
  }
  if (!res.ok) {
    const code = value?.error;
    if (code && rc.ERROR_CODES.includes(code)) throw new rc.RootcardError(code);
    throw new Error(`${url}: HTTP ${res.status}`);
  }
  return value;
}

/**
 * A typed host address made into the base URL to use ([HST-23]). An address with a path is a base URL already. For a
 * bare origin (`https://example.com`) the host pointer at `<origin>/.well-known/rootcard` is asked first: a pointer
 * names the host's base URL on that origin (`https://example.com/rootcard`), and without one (no answer, or not 200)
 * the origin itself is the base URL. A pointer that does not resolve is an error, never a silent fallback.
 */
async function resolveHost(text) {
  const typed = checkHost(text);
  if (!rc.isOrigin(typed)) return typed;
  const url = `${typed}${rc.WELL_KNOWN_PATH}`;
  let res;
  try {
    res = await fetch(url, { credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", redirect: "error" });
  } catch {
    return typed;
  }
  if (res.status !== 200) return typed;
  try {
    return rc.wellKnownBase(typed, rc.parseLimited(new Uint8Array(await res.arrayBuffer()), rc.WELL_KNOWN_LIMIT));
  } catch (e) {
    throw new Error(`${url} does not point to a rootcard host on ${typed}: ${explain(e)}`);
  }
}

async function hostList() {
  const typed = $("hosts").value.split(",").map((s) => s.trim()).filter(Boolean);
  const out = [];
  for (const t of typed) out.push(await resolveHost(t));
  return out;
}

/** [KT-2]: the newest log from the card, the account file and the hosts; a fork stops. */
async function gather() {
  let cardValue = await readFile($("cardFile"));
  if (!cardValue) {
    const key = await rc.parseRecoveryKey($("rkey").value);
    const realm = $("realm").value.trim();
    const username = $("username").value.trim();
    const keys = await rc.deriveRecoveryKeys(key, realm, username);
    const inc = await rc.inception(keys, realm, username);
    cardValue = await rc.recoveryCard(realm, username, await rc.accountId(inc), key);
  }
  const card = await rc.readCard(cardValue);
  const opts = { realms: [card.realm], now: now() };
  let log = card.log;
  let vault;
  let pub;
  const consider = async (candidate, source) => {
    await rc.verifyLog(candidate, opts);
    const order = await rc.compareLogs(log, candidate);
    if (order === "fork") throw new Error(`${source} holds a log that forks from the one already found. Extend the branch the primary host holds.`);
    if (order === "newer") log = candidate;
  };
  const file = await readFile($("accountFile"));
  if (file) {
    const a = await rc.importAccount(file, opts);
    if (a.state.account !== card.account) throw new Error("The account file is another identity.");
    await consider(a.log, "the account file");
    vault = a.vault?.value;
    pub = a.public?.value;
  }
  const hosts = await hostList();
  const st0 = await rc.verifyLog(log, opts);
  if (st0.instance) hosts.push(st0.instance.home.url);
  const notes = [];
  for (const h of [...new Set(hosts)]) {
    try {
      const v = await http("GET", `${apiRoot(h)}/id/${card.account}/log`);
      await consider(v.events, h);
    } catch (e) {
      notes.push(`${h}: ${explain(e)}`);
    }
  }
  const state = await rc.verifyLog(log, opts);
  await rc.checkRecoveryKey(state, card.keys.signSeed);
  current = { keys: card.keys, key: card.key, card: cardValue, log, state, vault, public: pub };
  return notes;
}

function describe(state) {
  const lines = [
    `Handle:   ${state.handle}`,
    `Account:  ${state.account}`,
    `Realm:    ${state.realm}`,
    `Version:  seq ${state.version.seq} ${state.version.hash}`,
  ];
  if (state.retired) lines.push("Status:   retired");
  else if (state.instance) lines.push(`Instance: seq ${state.instance.seq} (${state.instance.reason}) at ${state.instance.home.url}`);
  else lines.push("Instance: none");
  return lines.join("\n");
}

async function currentVault() {
  if (current.vault) {
    try {
      return { vault: current.vault, u: await rc.unlockVault(current.vault, current.state, { recovery: current.keys }) };
    } catch {}
  }
  if (!current.state.instance) throw new Error("No instance found: load the account file or enter the primary host.");
  const base = current.state.instance.home.url;
  const account = current.state.account;
  const ch = rc.parseChallenge(await http("POST", `${apiRoot(base)}/id/${account}/challenge`, { purpose: "fetch" }));
  const sig = await rc.ed25519Sign(current.keys.signSeed, rc.fetchMessage(account, ch.host, "recovery", ch.nonce, base));
  const v = await http("POST", `${apiRoot(base)}/id/${account}/fetch`, { lock: "recovery", nonce: ch.nonce, url: base, sig: rc.base64urlEncode(sig) });
  return { vault: v.vault, u: await rc.unlockVault(v.vault, current.state, { recovery: current.keys }) };
}

async function hostHome(base) {
  const d = await http("GET", `${apiRoot(base)}/host`);
  rc.parseKey(d.key, "ed25519");
  return { key: d.key, url: base };
}

function newSlot() {
  const password = $("newPassword").value;
  const username = current.state.username;
  rc.checkPassword(password, username);
  return { label: $("label").value.trim() || "Password", password, username, kdf: rc.KDF_DEFAULT };
}

async function submitInstance(base, mode, old) {
  const home = await hostHome(base);
  let publicData;
  if (current.public) {
    try {
      publicData = (await rc.verifyPublic(current.public, current.state)).data;
    } catch {}
  }
  const ni = await rc.newInstance(current.state, current.keys, old, publicData, mode, home, now(), random);
  const account = current.state.account;
  await http("POST", `${apiRoot(base)}/id/${account}/instance`, { events: current.log, instance: ni.event, vault: ni.vault, public: ni.public });
  const v = await http("GET", `${apiRoot(base)}/id/${account}/log`);
  const state = await rc.verifyLog(v.events, { realms: [current.state.realm], now: now() });
  const oldHome = current.state.instance?.home.url;
  let note = "";
  if (oldHome && oldHome !== base) {
    try {
      await http("POST", `${apiRoot(oldHome)}/id/${account}/events`, { events: v.events.slice(current.log.length) });
    } catch (e) {
      note = `\nCould not tell the previous primary host: ${explain(e)}`;
    }
  }
  current.log = v.events;
  current.state = state;
  current.vault = ni.vault;
  current.public = ni.public;
  current.vaultError = undefined;
  try {
    refreshSlots(await rc.verifyVault(ni.vault, state));
  } catch {}
  download(rc.accountFileName(state), rc.exportAccount(state, v.events, ni.public, ni.vault));
  return describe(state) + "\n\nThe new account file was downloaded." + note;
}

function refreshSlots(info) {
  $("slot").replaceChildren(...info.slots.map((s) => new Option(`${s.label} (${s.id})`, s.id)));
}

async function challengeOf(text) {
  const t = text.trim();
  if (/^[0-9a-fA-F]{64}$/.test(t)) return rc.hexDecode(t);
  return rc.statementChallenge(rc.parseJson(t));
}

const ops = {
  async restore() {
    const { u } = await currentVault();
    return submitInstance(await resolveHost($("targetHost").value), { restore: true }, u);
  },
  async fresh() {
    return submitInstance(await resolveHost($("targetHost").value), { fresh: newSlot() }, undefined);
  },
  async reset() {
    const { u } = await currentVault();
    return submitInstance(current.state.instance.home.url, { reset: newSlot() }, u);
  },
  async revoke() {
    const { u } = await currentVault();
    const id = $("slot").value;
    if (!id) throw new Error("Choose a password to revoke.");
    return submitInstance(current.state.instance.home.url, { revoke: [id] }, u);
  },
  async add() {
    const { vault, u } = await currentVault();
    const v = await rc.addSlot(u, vault, current.keys, newSlot(), random);
    await http("PUT", `${apiRoot(current.state.instance.home.url)}/id/${current.state.account}/vault`, { vault: v });
    current.vault = v;
    const info = await rc.verifyVault(v, current.state);
    refreshSlots(info);
    return "Passwords:\n" + info.slots.map((s) => `  ${s.label} (${s.id})`).join("\n");
  },
  async rotate() {
    const { vault, u } = await currentVault();
    const newKey = await rc.newRecoveryKey(current.state.realm, current.state.username, random);
    const r = await rc.rotateRecovery(current.state, current.log, current.keys, newKey, vault, u, now(), random);
    newKey.fill(0);
    // The new card is saved and shown before the rotation is sent: once the host has the event, the old key no longer
    // signs and the new card is the only copy of the new key ([KT-5]).
    download(`${current.state.username}-new.card.json`, r.card);
    const text = await rc.cardText(r.card);
    progress(text + "\nSending the rotation… Keep this card.");
    try {
      await http("POST", `${apiRoot(current.state.instance.home.url)}/id/${current.state.account}/events`, { events: [r.event], vault: r.vault });
    } catch (e) {
      throw new Error(
        `${explain(e)}\n\nThe rotation may or may not have reached the primary host. Keep both cards: the new card ` +
          `below (also downloaded) and the old one. Load the identity with the old card: if it answers that the ` +
          `recovery key is not the current one, the rotation arrived and the new card is current.\n\n${text}`,
      );
    }
    current = null;
    return text + "\nThe new card was downloaded. Destroy the old card, then open the identity with the new one.";
  },
  async retire() {
    if ($("retireConfirm").value !== current.state.username) throw new Error("Type the username to confirm.");
    const ev = await rc.retireEvent(current.state, current.keys.signSeed, now());
    await http("POST", `${apiRoot(current.state.instance.home.url)}/id/${current.state.account}/events`, { events: [ev] });
    return `${current.state.handle} is retired.`;
  },
  async card() {
    return rc.cardText(current.card);
  },
  async prove() {
    const p = await rc.prove(current.state, "recovery", current.keys.signSeed, await challengeOf($("proofStatement").value), $("proofRecipient").value);
    return rc.canonicalString(p);
  },
};

// ---- The page: what each action needs, and whether the loaded identity has it ----

/** Where an action sends something: "target" (the host typed for it), "home" (the primary host) or nowhere. */
const ACTIONS = {
  fresh: {
    title: "Start at a host",
    where: "target",
    text: "Puts the identity on a host with a new, empty account: a new vault with the password below, and an empty " +
      "profile. Use it for an identity that only exists on its card, or to start over. Data in an earlier account is " +
      "not carried over (use “Move to another host” for that).",
    host: "Host to start at",
  },
  restore: {
    title: "Move to another host",
    where: "target",
    text: "Makes a new account at the host you enter, carrying over data, profile and passwords from the current " +
      "vault. Use it to move, or to restore after a host is gone. The host may also be the current one.",
    host: "Host to move to",
  },
  reset: {
    title: "Reset a forgotten password",
    where: "home",
    text: "Starts a new account at the same host with one new password. Data and profile carry over; every old " +
      "password, vault copy and session stops working.",
  },
  add: { title: "Add a password", where: "home", text: "Adds another password to the vault. The others keep working." },
  revoke: {
    title: "Revoke a password",
    where: "home",
    text: "Starts a new account at the same host without the chosen password. The other passwords keep working, and " +
      "sessions signed in with the revoked one end.",
  },
  rotate: {
    title: "Rotate the recovery key",
    where: "home",
    text: "Replaces the recovery key. The new card is downloaded before anything is sent; keep it, and destroy the old " +
      "card once the rotation is done.",
  },
  card: { title: "Show the card", where: null, text: "Shows the recovery card as text, to print or copy onto paper." },
  prove: {
    title: "Make a root proof",
    where: null,
    text: "Signs a statement with the recovery key, so that anyone with your log can check that it came from you.",
  },
  retire: {
    title: "Retire the identity",
    where: "home",
    text: "Closes the identity for good: no host will accept anything for it again, and its handle stays taken. This " +
      "cannot be undone.",
  },
};

const NO_HOST =
  "The identity is not at any host that this page knows of. If it is at one, enter that host's address under " +
  "“Host address” above (or load the account file) and open the identity again. Otherwise start it at a host first.";

/** Why `op` cannot be done for the loaded identity now, or undefined. */
function blocked(op) {
  const st = current.state;
  if (st.retired) return op === "card" ? undefined : "The identity is retired. Nothing can change it any more.";
  if (op === "fresh" || op === "card" || op === "prove") return undefined;
  const home = st.instance?.home.url;
  if (!home) return NO_HOST;
  if (op === "retire") return undefined;
  if (current.vaultError) {
    return `This needs the vault, and it could not be opened: ${current.vaultError}. Load the account file, or check ` +
      "that the host can be reached.";
  }
  return undefined;
}

let picked = null;

function splitHandle(handle) {
  const i = handle.lastIndexOf("#");
  return i < 0 ? [handle, ""] : [handle.slice(0, i), handle.slice(i)];
}

function badge(text, kind) {
  const b = document.createElement("span");
  b.className = `badge ${kind}`;
  const dot = document.createElement("span");
  dot.className = "dot";
  b.append(dot, text);
  return b;
}

/** Draw the loaded identity and which actions it allows. */
function render() {
  $("actions").hidden = !current;
  if (!current) return;
  const st = current.state;
  const home = st.retired ? undefined : st.instance?.home.url;

  const [name, tag] = splitHandle(st.handle);
  const h = $("icHandle");
  const t = document.createElement("span");
  t.className = "tag";
  t.textContent = tag;
  h.replaceChildren(name, t);
  $("icAccount").textContent = st.account;
  $("icKind").textContent = st.retired ? "Retired" : home ? "Identity" : "Card only";
  $("idcard").className = `idcard${st.retired ? " retired" : home ? "" : " local"}`;

  const badges = [];
  if (st.retired) badges.push(badge("Retired", "bad"));
  else if (home) badges.push(badge("At a host", "ok"));
  else badges.push(badge("Not at any host", "warn"));
  if (home) badges.push(current.vaultError ? badge("Vault not available", "warn") : badge("Vault open", "teal"));
  $("badges").replaceChildren(...badges);

  const facts = [
    ["Realm", st.realm],
    ["Host", home ?? (st.retired ? "none (retired)" : "none")],
    ["Version", `seq ${st.version.seq}`],
  ];
  $("facts").replaceChildren(
    ...facts.flatMap(([k, v]) => {
      const dt = document.createElement("dt");
      dt.textContent = k;
      const dd = document.createElement("dd");
      dd.textContent = v;
      return [dt, dd];
    }),
  );

  const note = $("modeNote");
  if (st.retired) {
    note.className = "notice error";
    note.textContent = "This identity is retired. You can still show its card.";
  } else if (!home) {
    note.className = "notice warn";
    note.textContent =
      "This identity exists only on its card: no host stores it, so there is no account to sign in to yet. Choose " +
      "“Start at a host” to put it on one. Showing the card and making root proofs work offline. If the identity " +
      "already is at a host, enter that host's address above and open it again.";
  } else if (current.vaultError) {
    note.className = "notice warn";
    note.textContent = `The identity is at ${home}, but its vault could not be opened (${current.vaultError}). ` +
      "Actions that need the vault are unavailable; load the account file or try again when the host can be reached.";
  } else {
    note.className = "notice ok";
    note.textContent = `The identity is at ${home}. Changes are sent there, and after each one that makes a new ` +
      "account the new account file is downloaded.";
  }

  for (const tile of document.querySelectorAll("[data-pick]")) {
    const why = blocked(tile.dataset.pick);
    tile.classList.toggle("unavailable", Boolean(why));
    let req = tile.querySelector(".req");
    if (!req) {
      req = document.createElement("span");
      tile.append(req);
    }
    const where = ACTIONS[tile.dataset.pick].where;
    req.className = `req badge ${why ? "warn" : where ? "teal" : "ok"}`;
    req.textContent = why ? (where && !home ? "Needs a host" : "Unavailable") : where ? "Uses a host" : "Offline";
    tile.setAttribute("aria-pressed", String(tile.dataset.pick === picked));
  }
  $("opform").hidden = !picked;
  if (!picked) return;
  const a = ACTIONS[picked];
  const why = blocked(picked);
  $("opTitle").textContent = a.title;
  $("opText").textContent = a.text;
  const where = $("opWhere");
  if (a.where === "home") {
    where.className = "badge teal";
    where.textContent = home ? `Sends to ${home}` : "Needs a host";
  } else if (a.where === "target") {
    where.className = "badge teal";
    where.textContent = "Sends to the host you enter";
  } else {
    where.className = "badge ok";
    where.textContent = "Offline";
  }
  $("opBlocked").hidden = !why;
  $("opBlocked").textContent = why ?? "";
  if (a.host) $("targetHostLabel").textContent = a.host;
  for (const el of document.querySelectorAll("#opform [data-for]")) {
    el.hidden = !el.dataset.for.split(" ").includes(picked);
  }
  for (const b of document.querySelectorAll("#opform [data-op]")) b.disabled = Boolean(blocked(b.dataset.op));
}

/** Check a host address field while it is typed, and say what will be contacted. */
function watchHost(input) {
  const hint = $(`${input.id}Check`);
  const idle = hint.textContent;
  const check = () => {
    const parts = input.dataset.host === "list" ? input.value.split(",") : [input.value];
    const typed = parts.map((s) => s.trim()).filter(Boolean);
    if (typed.length === 0) {
      hint.className = "hint";
      hint.textContent = idle;
      input.removeAttribute("aria-invalid");
      return;
    }
    try {
      const bases = typed.map(checkHost).map((b) => (rc.isOrigin(b) ? `${b} (or the host its ${rc.WELL_KNOWN_PATH} names)` : b));
      hint.className = "hint good";
      hint.textContent = `✓ Will contact ${bases.join(", ")}`;
      input.removeAttribute("aria-invalid");
    } catch (e) {
      hint.className = "hint bad";
      hint.textContent = explain(e);
      input.setAttribute("aria-invalid", "true");
    }
  };
  input.addEventListener("input", check);
  check();
}

for (const input of document.querySelectorAll("[data-host]")) watchHost(input);

for (const tab of document.querySelectorAll("[role=tab]")) {
  tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll("[role=tab]")) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      $(t.getAttribute("aria-controls")).hidden = !on;
    }
  });
}

function createMode() {
  return $("nLocal").checked ? "local" : "host";
}
for (const r of document.querySelectorAll("[name=nWhere]")) {
  r.addEventListener("change", () => {
    for (const el of document.querySelectorAll("[data-when]")) el.hidden = el.dataset.when !== createMode();
  });
}

for (const tile of document.querySelectorAll("[data-pick]")) {
  tile.addEventListener("click", () => {
    picked = tile.dataset.pick;
    render();
    $("opform").scrollIntoView({ block: "nearest" });
  });
}

$("version").textContent = ROOTCARD_VERSION;
$("load").addEventListener("click", () =>
  run(async () => {
    current = null;
    picked = null;
    const notes = await gather();
    let extra = "";
    if (current.state.instance && !current.state.retired) {
      try {
        const { u } = await currentVault();
        refreshSlots(u.info);
      } catch (e) {
        current.vaultError = explain(e);
        extra = `\n(Vault not available: ${current.vaultError})`;
      }
    } else {
      $("slot").replaceChildren();
    }
    return describe(current.state) + extra + (notes.length ? "\n\n" + notes.join("\n") : "");
  }),
);
for (const b of document.querySelectorAll("[data-op]")) {
  b.addEventListener("click", () =>
    run(() => {
      if (!current) throw new Error("Open the identity first.");
      const why = blocked(b.dataset.op);
      if (why) throw new Error(why);
      return ops[b.dataset.op]();
    }),
  );
}
$("create").addEventListener("click", () =>
  run(async () => {
    const realm = $("nRealm").value.trim();
    const username = $("nUser").value.trim();
    if (createMode() === "host") checkHost($("nHost").value);
    if (createMode() === "host") rc.checkPassword($("nPassword").value, username);
    const base = createMode() === "host" ? await resolveHost($("nHost").value) : "";
    const rk = await rc.newRecoveryKey(realm, username, random); // usable in every browser ([CRY-9])
    let card;
    let file;
    let state;
    if (base) {
      const home = await hostHome(base);
      const reg = await rc.register(rk, realm, username, $("nPassword").value, "Password", home, now(), rc.KDF_DEFAULT, random);
      rk.fill(0);
      // The card is saved before anything is sent: once the host has the identity, the card is the only copy of its
      // recovery key ([CLT-1]).
      download(`${username}-${rc.tag(reg.account)}.card.json`, reg.card);
      await http("POST", `${apiRoot(home.url)}/id/register`, { log: reg.log, vault: reg.vault, public: reg.public });
      const v = await http("GET", `${apiRoot(home.url)}/id/${reg.account}/log`);
      state = await rc.verifyLog(v.events, { realms: [realm], now: now() });
      card = reg.card;
      file = rc.exportAccount(state, v.events, reg.public, reg.vault);
    } else {
      const keys = await rc.deriveRecoveryKeys(rk, realm, username);
      const inc = await rc.inception(keys, realm, username);
      state = await rc.verifyLog([inc], { realms: [realm] });
      card = await rc.recoveryCard(realm, username, state.account, rk);
      file = rc.exportAccount(state, [inc]);
    }
    rk.fill(0);
    if (!base) download(`${username}-${rc.tag(state.account)}.card.json`, card);
    download(rc.accountFileName(state), file);
    if (base) $("hosts").value = base;
    $("hosts").dispatchEvent(new Event("input"));
    const next = base
      ? `To manage it, choose “Open my identity”, load the card (the host ${base} is already filled in).`
      : "No host has it yet. To put it on one, choose “Open my identity”, load the card, then “Start at a host”.";
    return (await rc.cardText(card)) + "\n" + describe(state) + "\n\nThe card and the account file were downloaded. Keep the card offline.\n" + next;
  }),
);
$("verify").addEventListener("click", () =>
  run(async () => {
    const v = rc.parseJson($("vLog").value);
    const log = Array.isArray(v) ? v : v.log;
    const realm = log?.[0]?.body?.realm;
    const st = await rc.verifyProof(rc.parseJson($("vProof").value), log, await challengeOf($("vStatement").value), $("vRecipient").value, { realms: [realm], now: now() });
    return `Valid proof by ${st.handle}\n\n` + describe(st);
  }),
);
