// Builds keytool.html from tools/keytool.src.html and the package's own modules. A page opened from file:// cannot
// import ES modules, so the modules are inlined, each in its own function scope, in dependency order. No third-party
// code is involved. `node tools/build-keytool.mjs --check` fails if keytool.html is stale (run by npm test).

import { readFileSync, writeFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const read = (p) => readFileSync(new URL(p, root), "utf8");

/** Inline `entry` and everything it imports. */
export function bundle(entries) {
  const order = [];
  const seen = new Set();
  const visit = (name) => {
    if (seen.has(name)) return;
    seen.add(name);
    const src = read(`src/${name}`);
    for (const m of src.matchAll(/^import [^;]*? from "\.\/([a-z0-9-]+\.js)";$/gm)) visit(m[1]);
    order.push(name);
  };
  entries.forEach(visit);
  const out = ["const __modules = {};"];
  for (const name of order) {
    let src = read(`src/${name}`);
    const exported = [];
    src = src.replace(/^import \* as (\w+) from "\.\/([a-z0-9-]+\.js)";$/gm, (_, n, f) => `const ${n} = __modules["${f}"];`);
    src = src.replace(/^import \{([^}]*)\} from "\.\/([a-z0-9-]+\.js)";$/gms, (_, names, f) => {
      const list = names.split(",").map((x) => x.trim()).filter(Boolean).map((x) => x.replace(/ as /, ": "));
      return `const { ${list.join(", ")} } = __modules["${f}"];`;
    });
    src = src.replace(/^export \{([^}]*)\};$/gm, (_, names) => {
      for (const n of names.split(",").map((x) => x.trim()).filter(Boolean)) exported.push(n);
      return "";
    });
    src = src.replace(/^export ((?:async )?function\*? |const |let |class )(\w+)/gm, (_, kw, n) => {
      exported.push(n);
      return `${kw}${n}`;
    });
    if (/^(import|export) /m.test(src)) throw new Error(`${name}: unsupported import or export form`);
    out.push(`__modules["${name}"] = (() => {\n${src}\nreturn { ${exported.join(", ")} };\n})();`);
  }
  return out.join("\n");
}

const MODULES = ["index.js", "vault-index.js"];

/** The modules inlined into keytool.html. Every module that index.js or vault-index.js re-exports must be here. */
export const LIB = ["errors.js", "json.js", "encoding.js", "labels.js", "binding.js", "crypto.js", "keys.js", "recovery.js",
  "id.js", "log.js", "vaultcheck.js", "profile.js", "messages.js", "proof.js", "links-registry.js", "links.js", "file.js", "blake2b.js", "argon2.js", "vault.js",
  "account.js", "testing.js"];

export function build() {
  const template = read("tools/keytool.src.html");
  const lib = bundle(LIB);
  const app = read("tools/keytool.app.js");
  const marker = "<!-- SCRIPT -->";
  if (!template.includes(marker)) throw new Error("template without marker");
  const pkg = JSON.parse(read("package.json"));
  const script = `<script>\n"use strict";\n(() => {\nconst ROOTCARD_VERSION = ${JSON.stringify(pkg.version)};\n${lib}\n${app}\n})();\n</script>`;
  return template.replace(marker, () => script);
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) {
  const html = build();
  const target = new URL("keytool.html", root);
  if (process.argv.includes("--check")) {
    let current = "";
    try {
      current = readFileSync(target, "utf8");
    } catch {}
    if (current !== html) {
      console.error("keytool.html is stale: run `node tools/build-keytool.mjs`");
      process.exit(1);
    }
  } else {
    writeFileSync(target, html);
    console.log("wrote keytool.html");
  }
}
export { MODULES };
