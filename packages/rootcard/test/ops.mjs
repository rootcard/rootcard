// The vector operations of crates/xtask/src/ops.rs, in JavaScript. Each takes the vector's input and returns its
// output in the same JSON form; errors are thrown as RootcardError with the code. The module runs in Node and in
// browsers (tests/browser): the synchronous SHA-256 behind the deterministic test stream is set by the caller.

import * as rc from "../src/index.js";
import * as vault from "../src/vault-index.js";
import { testRandom } from "../src/testing.js";
import { hexDecode as hx, hexEncode as h, base64urlEncode as b64 } from "../src/encoding.js";
import { aesGcmDecrypt, aesGcmEncrypt, ed25519Public, ed25519PublicIs, ed25519Sign, ed25519Verify, hkdf, x25519, x25519Public } from "../src/crypto.js";
import { argon2id } from "../src/argon2.js";
import { recoverySignPublic } from "../src/recovery.js";

let sha256Sync = () => {
  throw new Error("setSha256Sync was not called");
};
/** Set the synchronous SHA-256 that `testRandom` needs: `node:crypto` in Node, precomputed digests in a browser. */
export function setSha256Sync(f) {
  sha256Sync = f;
}
const rng = (i) => testRandom(new TextEncoder().encode(i.random), sha256Sync);
const opts = (i) => {
  const o = { realms: i.realms ?? ["global"] };
  if (i.now !== undefined) o.now = i.now;
  return o;
};
const stateOf = (i) => rc.verifyLog(i.events, { realms: ["global"] });
const kdf = (k) => ({ m: k.m, t: k.t, p: 1 });
const home = async (x) => ({ key: rc.formatKey("ed25519", await ed25519Public(hx(x.seed))), url: x.url });

/** A text input: `text` (UTF-8) or `hex`, after `pad` spaces (crates/xtask/src/ops.rs `text_of`). */
const textOf = (i) => {
  const body = i.hex !== undefined ? hx(i.hex) : new TextEncoder().encode(i.text);
  const out = new Uint8Array((i.pad ?? 0) + body.length).fill(0x20);
  out.set(body, i.pad ?? 0);
  return out;
};
const responseOf = (r) => ("failed" in r ? null : r.txt !== undefined ? { txt: r.txt } : { body: textOf(r) });
const registryOf = (i) => (i.descriptors ? i.descriptors.map(rc.parseDescriptor) : rc.registry());
const descriptorOf = (i) => {
  const reg = registryOf(i);
  // As in Rust: the link is checked against [LNK-1] before the descriptor is looked up.
  const link = rc.parseLink(i.link);
  const d = rc.findDescriptor(reg, i.service ?? link.service);
  if (!d) throw new rc.RootcardError("unsupported");
  return d;
};

export const ops = {
  canonical: (i) => rc.canonicalString(rc.parseJson(hx(i.text))),
  base64url_encode: (i) => rc.base64urlEncode(hx(i.hex)),
  base64url_decode: (i) => h(rc.base64urlDecode(i.text)),
  base32_encode: (i) => rc.base32Encode(hx(i.hex)),
  base32_decode: (i) => h(i.lenient ? rc.base32DecodeLenient(i.text, i.len) : rc.base32Decode(i.text, i.len)),
  random: (i) => h(rng(i)(i.len)),
  parse_key: (i) => h(rc.parseKey(i.text, i.type)),
  format_recovery_key: (i) => rc.formatRecoveryKey(hx(i.key)),
  parse_recovery_key: async (i) => h(await rc.parseRecoveryKey(i.text)),
  derive_recovery_keys: async (i) => {
    const k = await rc.deriveRecoveryKeys(hx(i.key), i.realm, i.username);
    return {
      sign_seed: h(k.signSeed),
      sign_public: h(await recoverySignPublic(k)),
      box_secret: h(k.boxSecret),
      box_public: h(await x25519Public(k.boxSecret)),
    };
  },
  ed25519_sign: async (i) => {
    const seed = hx(i.seed);
    // A public key on record that the seed is checked against first ([IMP-6]); WebKit signs zero-led seeds only so.
    if (i.known !== undefined && !(await ed25519PublicIs(seed, hx(i.known)))) throw new rc.RootcardError("bad_key");
    return { public: h(await ed25519Public(seed)), sig: h(await ed25519Sign(seed, hx(i.msg))) };
  },
  ed25519_public_is: async (i) => ed25519PublicIs(hx(i.seed), hx(i.public)),
  new_recovery_key: async (i) => h(await rc.newRecoveryKey(i.realm, i.username, rng(i))),
  ed25519_verify: async (i) => {
    await ed25519Verify(hx(i.public), hx(i.msg), hx(i.sig));
    return true;
  },
  x25519: async (i) => ({ public: h(await x25519Public(hx(i.secret))), shared: h(await x25519(hx(i.secret), hx(i.peer))) }),
  hkdf: async (i) => h(await hkdf(hx(i.ikm), hx(i.salt), hx(i.info))),
  argon2id: (i) => h(argon2id(hx(i.password), hx(i.salt), { m: i.m, t: i.t, p: i.p })),
  aes_gcm_encrypt: async (i) => h(await aesGcmEncrypt(hx(i.key), hx(i.nonce), hx(i.plaintext), hx(i.aad))),
  aes_gcm_decrypt: async (i) => h(await aesGcmDecrypt(hx(i.key), hx(i.nonce), hx(i.ciphertext), hx(i.aad))),
  statement_challenge: async (i) => h(await rc.statementChallenge(i.statement)),
  check_realm: (i) => (rc.checkRealm(i.text), true),
  check_username: (i) => (rc.checkUsername(i.text), true),
  default_username_policy: (i) => rc.defaultUsernamePolicy(i.text),
  inception: async (i) => {
    const keys = await rc.deriveRecoveryKeys(hx(i.key), i.realm, i.username);
    const inc = await rc.inception(keys, i.realm, i.username);
    const account = await rc.accountId(inc);
    return { handle: rc.handle(i.username, account), account, inception: inc };
  },
  parse_handle: (i) => rc.parseHandle(i.text),
  extended_tags: (i) => rc.extendedTags(i.ids),
  verify_log: (i) => rc.verifyLog(i.events, opts(i)),
  extend_log: async (i) => rc.extendLog(await stateOf(i), i.new, opts(i)),
  verify_pending: async (i) => (await rc.verifyPending(await stateOf(i), i.pending, i.now), true),
  compare_logs: (i) => rc.compareLogs(i.a, i.b),
  add_receipt: (i) => rc.addReceipt({ ...i.event }, hx(i.host_seed)),
  register: async (i) => {
    const r = await vault.register(hx(i.key), i.realm, i.username, i.password, i.label, await home(i.home), i.time, kdf(i.kdf), rng(i));
    return { account: r.account, log: r.log, vault: r.vault, public: r.public, card: r.card };
  },
  verify_vault: async (i) => {
    const info = await rc.verifyVault(i.vault, await stateOf(i));
    return { rev: info.rev, gen: info.gen, slots: info.slots, hints: info.hints };
  },
  unlock_vault: async (i) => {
    const st = await stateOf(i);
    const secret = i.recovery_key
      ? { recovery: await rc.deriveRecoveryKeys(hx(i.recovery_key), st.realm, st.username) }
      : { lock: i.lock, password: i.password };
    const u = await vault.unlockVault(i.vault, st, secret);
    const contents = { v: 1, account_seed: b64(u.contents.accountSeed), data: u.contents.data };
    if (u.contents.known !== undefined) contents.known = u.contents.known;
    return {
      lock: u.lock,
      account_key: rc.formatKey("ed25519", await ed25519Public(u.contents.accountSeed)),
      lock_key: rc.formatKey("ed25519", await ed25519Public(u.lockSeed)),
      contents,
    };
  },
  change_password: (i) => vaultOp("change_password", i),
  add_slot: (i) => vaultOp("add_slot", i),
  update_contents: (i) => vaultOp("update_contents", i),
  rotate_recovery: (i) => vaultOp("rotate_recovery", i),
  new_instance: (i) => vaultOp("new_instance", i),
  vault_change: async (i) => {
    const c = await rc.vaultChange(i.old, i.new);
    return c.change === "password" ? { change: c.change, slot: c.slot, new: b64(c.new) } : c;
  },
  check_password: (i) => (vault.checkPassword(i.password, i.username), true),
  check_base_url: (i) => (rc.checkBaseUrl(i.url), true),
  well_known_base: (i) => rc.wellKnownBase(i.origin, i.document),
  check_data_key: (i) => (rc.checkDataKey(i.key), true),
  set_data: (i) => rc.setData(i.data, i.app, i.key, i.value),
  sign_public: async (i) => {
    const st = await stateOf(i);
    return rc.signPublic(st.account, st.instance.hash, i.rev, i.data, hx(i.account_seed));
  },
  verify_public: async (i) => rc.verifyPublic(i.profile, await stateOf(i)),
  login_message: (i) => {
    rc.parseKey(i.host, "ed25519");
    return h(rc.loginMessage(i.account, i.host, i.lock, b64(hx(i.nonce)), i.realm, i.url, i.version));
  },
  fetch_message: (i) => h(rc.fetchMessage(i.account, i.host, i.lock, b64(hx(i.nonce)), i.url)),
  change_message: (i) => h(rc.changeMessage(i.account, i.host, i.lock, b64(hx(i.new)), b64(hx(i.nonce)), i.url)),
  login_sign: async (i) => rc.signLogin(await stateOf(i), i.challenge, i.url, i.lock, hx(i.account_seed), hx(i.lock_seed)),
  login_verify: async (i) => {
    const st = await stateOf(i);
    // The Rust core parses the request, then takes the lock key parsed: the same order here, so a malformed key fails
    // the same way.
    rc.parseLoginRequest(i.request);
    rc.parseKey(i.lock_key, "ed25519");
    await rc.verifyLogin(i.request, st.realm, st.instance.home.key, st.instance.account_key, i.lock_key);
    return true;
  },
  prove: async (i) => rc.prove(await stateOf(i), i.by, hx(i.seed), hx(i.challenge), i.recipient),
  verify_proof: async (i) => (await rc.verifyProof(i.proof, i.log, hx(i.challenge), i.recipient, opts(i))).version,
  export_account: async (i) => rc.exportAccount(await stateOf(i), i.events, i.public, i.vault),
  import_account: async (i) => {
    const a = await rc.importAccount(i.file, opts(i));
    const out = { state: a.state };
    if (a.public) out.public_rev = a.public.info.rev;
    if (a.vault) out.vault_rev = a.vault.info.rev;
    return out;
  },
  read_card: async (i) => {
    const c = await rc.readCard(i.card);
    return { account: c.account, realm: c.realm, username: c.username, state: c.state };
  },
  card_text: (i) => rc.cardText(i.card),
  parse_response_json: (i) => {
    const v = rc.parseResponseJson(hx(i.text));
    return v === undefined ? {} : { value: v };
  },
  link_token: (i) => rc.linkToken(i.account),
  find_link_token: (i) => rc.findLinkToken(textOf(i), i.account),
  parse_descriptor: (i) => {
    const d = rc.parseDescriptor(i.descriptor);
    return { service: d.service, rev: d.rev, retired: d.retired };
  },
  parse_links: (i) => rc.parseLinks(i.data, registryOf(i)),
  links_value: (i) => {
    const reg = registryOf(i);
    // As in Rust, the input is converted to links before the library sees it.
    return rc.linksValue(i.links.map(rc.parseLink), reg);
  },
  link_requests: (i) => rc.linkRequests(i.link, descriptorOf(i)),
  link_display: (i) => rc.linkDisplay(i.link, descriptorOf(i)),
  check_link: (i) => {
    const d = descriptorOf(i);
    rc.checkLink(i.link, i.account, d, i.responses.map(responseOf));
    return true;
  },
};

async function vaultOp(op, i) {
  const st = await stateOf(i);
  const keys = await rc.deriveRecoveryKeys(hx(i.recovery_key), st.realm, st.username);
  const u = await vault.unlockVault(i.vault, st, { recovery: keys });
  const random = rng(i);
  if (op === "change_password") {
    const r = await vault.changePassword(u, i.vault, i.lock, i.password, st.username, kdf(i.kdf), random);
    return { vault: r.vault, new: b64(r.new) };
  }
  if (op === "add_slot") return vault.addSlot(u, i.vault, keys, { label: i.label, password: i.password, username: st.username, kdf: kdf(i.kdf) }, random);
  if (op === "update_contents") return vault.updateContents(u, i.vault, { ...u.contents, data: i.data }, random);
  if (op === "rotate_recovery") {
    const r = await vault.rotateRecovery(st, i.events, keys, hx(i.new_key), i.vault, u, i.time, random);
    return { event: r.event, vault: r.vault, card: r.card };
  }
  const slot = i.slot ? { label: i.slot.label, password: i.slot.password, username: st.username, kdf: kdf(i.slot.kdf) } : undefined;
  const mode = i.mode === "restore" ? { restore: true } : i.mode === "revoke" ? { revoke: i.drop ?? [] } : i.mode === "reset" ? { reset: slot } : { fresh: slot };
  const pub = i.public ? (await rc.verifyPublic(i.public, st)).data : undefined;
  const r = await vault.newInstance(st, keys, u, pub, mode, await home(i.home), i.time, random);
  return { event: r.event, vault: r.vault, public: r.public };
}
