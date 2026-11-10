// Rules that the shared vectors cannot express, checked on this package directly (the Rust side is in
// crates/rootcard/tests/flows.rs and crates/rootcard-host/tests/rules.rs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import * as rc from "../src/index.js";
import { register, unlockVault, checkContents } from "../src/vault-index.js";
import { testRandom } from "../src/testing.js";

const vectors = (name) => JSON.parse(readFileSync(new URL(`../../../spec/vectors/${name}`, import.meta.url), "utf8"));
const enc = new TextEncoder();

/** A valid but non-canonical serialization: members in reverse order, whitespace, and `A` and `/` as escapes. */
function loose(v) {
  const str = (s) => '"' + [...s].map((c) => (c === "A" ? "\\u0041" : c === "/" ? "\\/" : JSON.stringify(c).slice(1, -1))).join("") + '"';
  if (Array.isArray(v)) return "[ " + v.map(loose).join(" , ") + " ]";
  if (typeof v === "object") return "{ " + Object.keys(v).reverse().map((k) => `${str(k)} : ${loose(v[k])}`).join(",\n  ") + " }";
  if (typeof v === "string") return str(v);
  return String(v);
}

test("[CJ-7] a log in another serialization verifies to the same state: hashes are over canonical bytes", async () => {
  const { input } = vectors("log.json").vectors.find((v) => v.name === "registered log");
  const text = "\n" + loose(input.events) + "\n";
  assert.notEqual(text, rc.canonicalString(input.events));
  const parsed = rc.parseJson(enc.encode(text));
  const expected = await rc.verifyLog(input.events, { realms: ["global"] });
  assert.deepEqual(await rc.verifyLog(parsed, { realms: ["global"] }), expected);
  for (let i = 0; i < parsed.length; i++) {
    assert.deepEqual(await rc.eventHash(parsed[i]), await rc.eventHash(input.events[i]));
  }
  assert.equal(rc.canonicalString(parsed), rc.canonicalString(input.events));
});

test("[VLT-9] the vault contents never hold the recovery key", async () => {
  const random = testRandom(enc.encode("rules-vlt9"), (m) => new Uint8Array(createHash("sha256").update(m).digest()));
  const password = "correct horse battery staple";
  const hostSeed = new Uint8Array(32).fill(0xa1);
  const rk = await rc.newRecoveryKey("global", "Astra", random);
  const home = { key: rc.formatKey("ed25519", await rc.ed25519Public(hostSeed)), url: "https://a.example" };
  const reg = await register(rk, "global", "Astra", password, "Laptop", home, 1_800_000_000, rc.KDF_MIN, random);
  const log = [reg.log[0], await rc.addReceipt(structuredClone(reg.log[1]), hostSeed)];
  const state = await rc.verifyLog(log, { realms: ["global"] });
  const keys = await rc.deriveRecoveryKeys(rk, "global", "Astra");
  const lock = (await rc.verifyVault(reg.vault, state)).slots[0].id;
  for (const secret of [{ lock, password }, { recovery: keys }]) {
    const { contents } = await unlockVault(reg.vault, state, secret);
    const text = rc.canonicalString({ seed: rc.base64urlEncode(contents.accountSeed), data: contents.data, known: contents.known ?? {} });
    for (const k of [rk, keys.signSeed, keys.boxSecret]) {
      assert.ok(!text.includes(rc.base64urlEncode(k)), "a recovery secret is in the contents");
      assert.ok(!text.includes(rc.hexEncode(k)), "a recovery secret is in the contents");
    }
    assert.ok(!text.includes(await rc.formatRecoveryKey(rk)), "the recovery key is in the contents");
  }
  // Contents with a member for it are refused ([VLT-7]).
  const contents = { v: 1, account_seed: rc.base64urlEncode(new Uint8Array(32).fill(1)), data: {} };
  checkContents(contents);
  assert.throws(() => checkContents({ ...contents, recovery_key: rc.base64urlEncode(rk) }), (e) => e.code === "bad_field");
});
