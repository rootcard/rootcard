// Linked accounts end to end (SPEC §12.3): a signed profile with links, verified, parsed and checked with recorded
// answers, as docs/GETTING_STARTED.md §4.1 does it. The byte-level rules are in spec/vectors/link.json.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as rc from "../src/index.js";
import { hexDecode } from "../src/encoding.js";

const vectors = JSON.parse(readFileSync(new URL("../../../spec/vectors/profile.json", import.meta.url), "utf8")).vectors;
const signing = vectors.find((v) => v.op === "sign_public" && !v.error).input;

test("a link in a signed profile verifies with its answers [LNK-1, LNK-3, LNK-4, LNK-10]", async () => {
  const state = await rc.verifyLog(signing.events, { realms: ["global"] });
  const registry = rc.registry();
  const links = [
    { service: "github", name: "alice", uid: "583231", ref: "bio" },
    { service: "web", name: "astra.dev" },
  ];
  const data = rc.setData({ "user.name": "Astra" }, "xigna", rc.LINKS_KEY, rc.linksValue(links, registry));
  const profile = await rc.signPublic(state.account, state.instance.hash, 1, data, hexDecode(signing.account_seed));
  const verified = await rc.verifyPublic(profile, state);
  const entries = rc.parseLinks(verified.data, registry);
  assert.deepEqual(entries.map((e) => e.status), ["ok", "ok"]);

  const token = rc.linkToken(state.account);
  const answers = {
    "https://api.github.com/user/583231": { body: JSON.stringify({ login: "Alice", id: 583231, bio: `I am ${token}` }) },
    "https://astra.dev/.well-known/rootcard-link": { body: `${token}\n` },
  };
  for (const { link } of entries) {
    const d = rc.findDescriptor(registry, link.service);
    const reqs = rc.linkRequests(link, d);
    rc.checkLink(link, state.account, d, reqs.map((r) => answers[r.url] ?? null));
  }

  // The same answers name another identity: the link is not verified.
  const other = rc.base32Encode(new Uint8Array(32).fill(9));
  const d = rc.findDescriptor(registry, "web");
  assert.throws(() => rc.checkLink(links[1], other, d, [answers["https://astra.dev/.well-known/rootcard-link"]]), {
    code: "token_missing",
  });
});

test("links in a profile are data: an invalid value leaves the profile valid [LNK-2, DAT-5]", async () => {
  const state = await rc.verifyLog(signing.events, { realms: ["global"] });
  const data = { "user.links": { v: 1, links: [{ service: "web", name: "localhost" }, { service: "dns", name: "example.org" }] } };
  const profile = await rc.signPublic(state.account, state.instance.hash, 1, data, hexDecode(signing.account_seed));
  const { data: d } = await rc.verifyPublic(profile, state);
  assert.deepEqual(rc.parseLinks(d, rc.registry()).map((e) => e.status), ["bad_link", "ok"]);
});
