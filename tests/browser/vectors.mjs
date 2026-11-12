// Every shared vector (spec/vectors) through the JavaScript core in a browser, with the same operations as the Node
// tests (packages/rootcard/test/ops.mjs). WebCrypto's Ed25519 and X25519 differ between engines, and keytool.html runs
// in browsers, so the vectors must pass in each engine, not only in Node. Results go to `window.results`.

import { ops, setSha256Sync } from "../../packages/rootcard/test/ops.mjs";
import { canonicalString, RootcardError } from "../../packages/rootcard/src/index.js";

const FILES = ["primitives.json", "log.json", "vault.json", "profile.json", "proof.json", "file.json", "link.json"];
// Blocks of the deterministic stream precomputed per vector: 32 bytes each. A vector that draws more fails loudly.
const BLOCKS = 512;

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// `testRandom` needs a synchronous SHA-256 of `seed ‖ be32(counter)`. WebCrypto is asynchronous, so the digests for a
// vector's seed are computed before the vector runs and looked up by input.
async function prepare(seedText) {
  const seed = new TextEncoder().encode(seedText);
  const table = new Map();
  await Promise.all(
    Array.from({ length: BLOCKS }, async (_, counter) => {
      const m = new Uint8Array(seed.length + 4);
      m.set(seed);
      new DataView(m.buffer).setUint32(seed.length, counter);
      table.set(hex(m), new Uint8Array(await crypto.subtle.digest("SHA-256", m)));
    }),
  );
  setSha256Sync((m) => {
    const d = table.get(hex(m));
    if (!d) throw new Error(`the vector drew more than ${BLOCKS * 32} random bytes`);
    return d;
  });
}

async function run() {
  const failures = [];
  let pass = 0;
  for (const file of FILES) {
    const { vectors } = await (await fetch(`../../spec/vectors/${file}`)).json();
    for (const v of vectors) {
      const name = `${file}: ${v.name}`;
      try {
        if (v.input && typeof v.input.random === "string") await prepare(v.input.random);
        const op = ops[v.op];
        if (!op) throw new Error(`no operation ${v.op}`);
        let out;
        try {
          out = await op(v.input);
        } catch (e) {
          if (!(e instanceof RootcardError)) throw e;
          if (e.code !== (v.error ?? "(no error)")) throw new Error(`unexpected error ${e.code}, expected ${v.error ?? "output"}`);
          pass++;
          continue;
        }
        if (v.error !== undefined) throw new Error(`expected ${v.error}, got output`);
        if (canonicalString(out) !== canonicalString(v.output)) throw new Error("output differs");
        pass++;
      } catch (e) {
        failures.push(`${name}: ${e && e.message ? e.message : e}`);
      }
    }
  }
  return { userAgent: navigator.userAgent, pass, fail: failures.length, failures };
}

run().then(
  (r) => {
    window.results = r;
    document.getElementById("out").textContent = JSON.stringify(r, null, 2);
  },
  (e) => {
    window.results = { pass: 0, fail: 1, failures: [`harness: ${e && e.stack ? e.stack : e}`] };
  },
);
