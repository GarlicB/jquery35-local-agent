"use strict";
const fs = require("fs");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const cp = require("child_process");
const os = require("os");

const TOOL_NAME = "jquery35-local-agent";
const TOOL_VERSION = "5.3.0";
const TARGET_JQUERY_FLOOR_VERSION = "3.5.0";
const DEFAULT_JQUERY_VERSION = "3.5.1";
const DEFAULT_MIGRATE_VERSION = "3.6.0";
const CVE_ID = "CVE-2020-11023";
const PROBE_FILE_NAME = "jquery35-test-probe.js";
const PROBE_MARKER = "JQUERY35_RUNTIME_PROBE";
const PAGE_EXTS = [".jsp", ".jspx", ".html", ".htm", ".tag", ".tagx", ".inc", ".xhtml"];
const TEXT_EXTS = PAGE_EXTS.concat([".js", ".css"]);
const EXCLUDE_DIRS = Object.assign(Object.create(null), { ".git": 1, ".svn": 1, ".hg": 1, "node_modules": 1, "target": 1, "build": 1, "dist": 1, ".idea": 1, ".settings": 1 });
const MODES = ["plan", "autofix", "patch-jquery", "probe", "lab", "verify-clean", "pr-report", "packet", "review-pack", "self-test"];

const DEFAULT_PATH_VARS = {
  "${js}": "/js",
  "${css}": "/css",
  "${images}": "/images",
  "${img}": "/images",
  "${context}": "",
  "${ctx}": "",
  "${pageContext.request.contextPath}": "",
  "${request.contextPath}": ""
};

const DEFAULT_VENDOR_PATTERNS = [
  "resources/jqgrid/", "jquery-ui", "jquery.ui", "select2", "autonumeric",
  "jqgrid", "jquery.jqgrid", "grid.locale", "bootstrap", "jquery.validate",
  "jquery-validate", "datepicker", "/plugin/", "/plugins/", "/lib/", "/libs/",
  "/vendor/", "/vendors/", "/thirdparty/", "/third-party/"
];

const DEFAULT_APP_HINTS = ["js/util.js", "js/common.js"];
const DEFAULT_IGNORE_ATTR_PATTERNS = ["aria-"];
const BOOL_ATTRS = Object.assign(Object.create(null), { disabled: 1, readonly: 1, checked: 1, selected: 1 });

const TAINT_NAMES = Object.create(null);
["response", "responsetext", "result", "resultdata", "data", "html", "content",
  "input", "value", "msg", "message", "param", "params", "title", "name",
  "formatted", "returnvalue", "doctypeselect", "cardlist", "alter", "altername",
  "json", "list", "rows", "body", "text", "resp", "res"].forEach(function (n) { TAINT_NAMES[n] = 1; });

const SKIP_CALLBACK_BASES = Object.assign(Object.create(null), { console: 1, window: 1, Math: 1, JSON: 1, logger: 1, log: 1, alert: 1 });

const PRIORITY_RANK = Object.assign(Object.create(null), {
  Critical: 90, XssHigh: 80, Manual: 70, Review: 60,
  AutoFixed2: 50, AutoFixed: 40, VendorReview: 30, StaticHtmlLow: 20, Ignored: 10
});

function log(msg) { process.stdout.write("[jq35] " + msg + "\n"); }
function warn(msg) { process.stdout.write("[jq35][WARN] " + msg + "\n"); }
function fail(msg) { process.stdout.write("[jq35][FAIL] " + msg + "\n"); }

function ensureDir(p) { fs.mkdirSync(p, { recursive: true }); }
function readLatin1(p) { return fs.readFileSync(p).toString("latin1"); }
function writeLatin1(p, text) { ensureDir(path.dirname(p)); fs.writeFileSync(p, Buffer.from(text, "latin1")); }
function readUtf8(p) { return fs.readFileSync(p, "utf8"); }
function writeUtf8(p, text, bom) { ensureDir(path.dirname(p)); fs.writeFileSync(p, (bom ? "\uFEFF" : "") + text, "utf8"); }
function exists(p) { try { fs.statSync(p); return true; } catch (e) { return false; } }
function isDir(p) { try { return fs.statSync(p).isDirectory(); } catch (e) { return false; } }
function toPosix(p) { return String(p).split(path.sep).join("/"); }
function trunc(s, n) { s = String(s == null ? "" : s).replace(/[\r\n\t]+/g, " "); return s.length > n ? s.slice(0, n) + "..." : s; }
function uniq(arr) { const seen = {}; const out = []; arr.forEach(function (a) { if (!seen[a]) { seen[a] = 1; out.push(a); } }); return out; }
function positiveIntOpt(raw, def) { const n = parseInt(raw, 10); return (Number.isFinite(n) && n > 0) ? n : def; }
function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function htmlEsc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function xmlEsc(s) { return htmlEsc(s).replace(/'/g, "&apos;").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, ""); }

function csvCell(v) {
  let s = String(v == null ? "" : v);
  if (/[",\r\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}
function writeCsv(file, header, rows) {
  const lines = [header.map(csvCell).join(",")];
  rows.forEach(function (r) { lines.push(r.map(csvCell).join(",")); });
  writeUtf8(file, lines.join("\r\n") + "\r\n", true);
}

function isUnderDir(child, parent) {
  if (!parent) return false;
  const c = path.resolve(child).toLowerCase() + path.sep;
  const p = path.resolve(parent).toLowerCase() + path.sep;
  return c.indexOf(p) === 0;
}

function walkFiles(root, excludeAbs) {
  const out = [];
  function rec(dir) {
    let names;
    try { names = fs.readdirSync(dir); } catch (e) { return; }
    names.sort();
    for (let i = 0; i < names.length; i++) {
      const abs = path.join(dir, names[i]);
      let st;
      try { st = fs.statSync(abs); } catch (e) { continue; }
      if (st.isDirectory()) {
        if (EXCLUDE_DIRS[names[i].toLowerCase()]) continue;
        let skip = false;
        for (let k = 0; k < excludeAbs.length; k++) {
          if (path.resolve(abs).toLowerCase() === path.resolve(excludeAbs[k]).toLowerCase() || isUnderDir(abs, excludeAbs[k])) { skip = true; break; }
        }
        if (skip) continue;
        rec(abs);
      } else {
        out.push({ abs: abs, size: st.size });
      }
    }
  }
  rec(root);
  return out;
}

function lineStartsOf(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}
function lineOf(starts, idx) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= idx) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}
function lineTextAt(text, starts, lineNo) {
  const s = starts[lineNo - 1];
  const e = lineNo < starts.length ? starts[lineNo] : text.length;
  return text.slice(s, e).replace(/[\r\n]+$/, "");
}
function detectEol(text) {
  const crlf = (text.match(/\r\n/g) || []).length;
  const lf = (text.match(/\n/g) || []).length;
  return crlf > 0 && crlf * 2 >= lf ? "\r\n" : "\n";
}

function maskJs(src, keepStrings) {
  const n = src.length;
  const out = new Array(n);
  let i = 0;
  let lastSig = "";
  let lastWord = "";
  let prevWasWord = false;
  const REGEX_WORDS = { "return": 1, "typeof": 1, "instanceof": 1, "in": 1, "of": 1, "new": 1, "delete": 1, "void": 1, "case": 1, "do": 1, "else": 1, "throw": 1 };
  while (i < n) {
    const c = src[i];
    const d = i + 1 < n ? src[i + 1] : "";
    if (c === "/" && d === "/") {
      while (i < n && src[i] !== "\n") { out[i] = " "; i++; }
      continue;
    }
    if (c === "/" && d === "*") {
      out[i] = " "; out[i + 1] = " "; i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) { out[i] = src[i] === "\n" ? "\n" : " "; i++; }
      if (i < n) { out[i] = " "; out[i + 1] = " "; i += 2; }
      continue;
    }
    if (c === '"' || c === "'") {
      const q = c;
      out[i] = q; i++;
      while (i < n) {
        if (src[i] === "\\" && i + 1 < n) { out[i] = keepStrings ? src[i] : " "; out[i + 1] = keepStrings ? src[i + 1] : " "; i += 2; continue; }
        if (src[i] === q) { out[i] = q; i++; break; }
        if (src[i] === "\n") { out[i] = "\n"; i++; break; }
        out[i] = keepStrings ? src[i] : " "; i++;
      }
      lastSig = q; prevWasWord = false;
      continue;
    }
    if (c === "`") {
      out[i] = "`"; i++;
      while (i < n) {
        if (src[i] === "\\" && i + 1 < n) { out[i] = " "; out[i + 1] = " "; i += 2; continue; }
        if (src[i] === "`") { out[i] = "`"; i++; break; }
        out[i] = src[i] === "\n" ? "\n" : (keepStrings ? src[i] : " "); i++;
      }
      lastSig = "`"; prevWasWord = false;
      continue;
    }
    if (c === "/") {
      let regexOk = false;
      if (lastSig === "") regexOk = true;
      else if ("(,=:[!&|?{};+-*%~^<>".indexOf(lastSig) >= 0) regexOk = true;
      else if (/[A-Za-z0-9_$]/.test(lastSig) && REGEX_WORDS[lastWord]) regexOk = true;
      if (regexOk) {
        out[i] = "/"; i++;
        let inClass = false;
        while (i < n) {
          if (src[i] === "\\" && i + 1 < n) { out[i] = " "; out[i + 1] = " "; i += 2; continue; }
          if (src[i] === "[") { inClass = true; out[i] = " "; i++; continue; }
          if (src[i] === "]") { inClass = false; out[i] = " "; i++; continue; }
          if (src[i] === "/" && !inClass) { out[i] = "/"; i++; break; }
          if (src[i] === "\n") { out[i] = "\n"; i++; break; }
          out[i] = " "; i++;
        }
        while (i < n && /[a-z]/i.test(src[i])) { out[i] = src[i]; i++; }
        lastSig = "/"; prevWasWord = false;
        continue;
      }
    }
    out[i] = c;
    if (/\s/.test(c)) {
      prevWasWord = false;
    } else {
      lastSig = c;
      if (/[A-Za-z0-9_$]/.test(c)) {
        lastWord = prevWasWord ? lastWord + c : c;
        prevWasWord = true;
      } else {
        lastWord = "";
        prevWasWord = false;
      }
    }
    i++;
  }
  return out.join("");
}

function matchParen(masked, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < masked.length; i++) {
    const c = masked[i];
    if (c === "(") depth++;
    else if (c === ")") { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function matchBrace(masked, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < masked.length; i++) {
    const c = masked[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function splitTopArgs(masked, start, end) {
  const parts = [];
  let depth = 0;
  let s = start;
  for (let i = start; i < end; i++) {
    const c = masked[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) { parts.push({ s: s, e: i }); s = i + 1; }
  }
  if (end > s || parts.length > 0) parts.push({ s: s, e: end });
  if (parts.length === 1 && masked.slice(parts[0].s, parts[0].e).trim() === "") return [];
  return parts;
}

function receiverInfo(masked, orig, dotIdx) {
  let i = dotIdx - 1;
  let end = -1;
  let guard = 0;
  while (i >= 0 && guard++ < 600) {
    while (i >= 0 && /\s/.test(masked[i])) i--;
    if (i < 0) break;
    if (end < 0) end = i + 1;
    const c = masked[i];
    if (c === ")" || c === "]") {
      let depth = 0;
      while (i >= 0) {
        const ch = masked[i];
        if (ch === ")" || ch === "]") depth++;
        else if (ch === "(" || ch === "[") { depth--; if (depth === 0) break; }
        i--;
      }
      if (i < 0) break;
      i--;
      continue;
    }
    if (/[A-Za-z0-9_$]/.test(c)) {
      const e2 = i;
      while (i >= 0 && /[A-Za-z0-9_$]/.test(masked[i])) i--;
      const base = masked.slice(i + 1, e2 + 1);
      let j = i;
      while (j >= 0 && /\s/.test(masked[j])) j--;
      if (j >= 0 && masked[j] === ".") { i = j - 1; continue; }
      const start = i + 1;
      return { base: base, start: start, end: end, text: orig.slice(start, end) };
    }
    if (c === "}") return { base: "}", start: i, end: end, text: "" };
    return { base: "", start: i + 1, end: end, text: orig.slice(i + 1, end) };
  }
  return { base: "", start: Math.max(0, dotIdx), end: dotIdx, text: "" };
}

function isJqReceiver(info) {
  if (!info) return false;
  if (info.base === "$" || info.base === "jQuery") return true;
  if (info.base && info.base.charAt(0) === "$" && info.base.length > 1) return true;
  return false;
}
function isWindowJq(info) {
  return /^(\$|jQuery)\s*\(\s*(window|top|self)\s*\)$/.test(String(info.text || "").trim());
}

function versionParts(v) {
  return String(v || "").split(".").map(function (x) { const n = parseInt(x, 10); return isNaN(n) ? 0 : n; });
}
function versionLt(a, b) {
  const pa = versionParts(a), pb = versionParts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}
function versionFromName(name) {
  const m = String(name).match(/(\d+(?:\.\d+){1,3})/);
  return m ? m[1] : "";
}
function sniffJqueryVersion(absPath) {
  try {
    const fd = fs.openSync(absPath, "r");
    const buf = Buffer.alloc(4096);
    const n = fs.readSync(fd, buf, 0, 4096, 0);
    fs.closeSync(fd);
    const head = buf.slice(0, n).toString("latin1");
    let m = head.match(/jQuery\s+(?:JavaScript Library\s+)?v(\d+(?:\.\d+){1,3})/i);
    if (m) return m[1];
    m = head.match(/jquery:\s*["'](\d+(?:\.\d+){1,3})["']/i);
    if (m) return m[1];
    m = head.match(/fn\.jquery\s*=\s*["'](\d+(?:\.\d+){1,3})["']/i);
    if (m) return m[1];
    return "";
  } catch (e) { return ""; }
}

function fileNameOf(ref) {
  const q = String(ref).split(/[?#]/)[0];
  const idx = q.lastIndexOf("/");
  return (idx >= 0 ? q.slice(idx + 1) : q).toLowerCase();
}
function isJqueryCoreName(name) {
  if (/jquery[-.]migrate/.test(name)) return false;
  if (/jquery[-.]ui/.test(name)) return false;
  return /^jquery([-.]?\d[\d.]*)?(\.slim)?(\.min)?\.js$/.test(name);
}
function isMigrateName(name) {
  return /jquery[-.]migrate/.test(name) && /\.js$/.test(name);
}

function classifyLib(rel, profile) {
  const relLower = toPosix(rel).toLowerCase();
  const name = fileNameOf(relLower);
  if (name === PROBE_FILE_NAME) return "probe";
  if (isMigrateName(name)) return "jquery-migrate";
  if (/jquery[-.]ui/.test(name) || /jquery[-.]ui/.test(relLower)) return "jquery-ui";
  if (/jqgrid|jquery\.jqgrid|grid\.locale/.test(name) || /\/jqgrid\//.test(relLower)) return "jqgrid";
  if (/select2/.test(name)) return "select2";
  if (/autonumeric/.test(name)) return "autoNumeric";
  if (/bootstrap/.test(name)) return "bootstrap";
  if (/jquery[-.]validat/.test(name)) return "jquery-validate";
  if (/datepicker/.test(name)) return "datepicker";
  if (isJqueryCoreName(name)) return "jquery-core";
  for (let i = 0; i < profile.appScriptHints.length; i++) {
    if (relLower.indexOf(profile.appScriptHints[i].toLowerCase()) >= 0) return "app";
  }
  for (let i = 0; i < profile.vendorPatterns.length; i++) {
    if (relLower.indexOf(profile.vendorPatterns[i].toLowerCase()) >= 0) return "vendor-other";
  }
  if (/\.min\.js$/.test(name) || /\.min\.css$/.test(name)) return "vendor-other";
  return "app";
}

function isVendorLib(lib) {
  return lib === "jquery-ui" || lib === "jqgrid" || lib === "select2" || lib === "autoNumeric" ||
    lib === "bootstrap" || lib === "jquery-validate" || lib === "datepicker" || lib === "vendor-other";
}

function isMinifiedFile(rel, text) {
  if (/\.min\.(js|css)$/i.test(rel)) return true;
  if (!text) return false;
  const sample = text.slice(0, 20000);
  const lines = sample.split("\n");
  let maxLen = 0;
  for (let i = 0; i < lines.length; i++) if (lines[i].length > maxLen) maxLen = lines[i].length;
  return maxLen > 3000;
}

function defaultProfile() {
  return {
    webContentDir: "WebContent",
    pathVariables: Object.assign({}, DEFAULT_PATH_VARS),
    vendorPatterns: DEFAULT_VENDOR_PATTERNS.slice(),
    appScriptHints: DEFAULT_APP_HINTS.slice(),
    ignoreAttrPatterns: DEFAULT_IGNORE_ATTR_PATTERNS.slice(),
    jquery: {
      targetVersion: DEFAULT_JQUERY_VERSION,
      migrateVersion: DEFAULT_MIGRATE_VERSION,
      coreFile: "jquery-" + DEFAULT_JQUERY_VERSION + ".min.js",
      migrateFile: "jquery-migrate-" + DEFAULT_MIGRATE_VERSION + ".min.js",
      newJquerySrc: "",
      newMigrateSrc: "",
      migrateTrace: false
    },
    probe: {
      enabled: true,
      injectTargetHints: ["WEB-INF/layouts/common_script_lib.jsp"]
    },
    learnedWrappers: [],
    learnedFindings: [],
    sensitiveIdentifiers: []
  };
}

function loadProfile(opts, sourceRoot) {
  const prof = defaultProfile();
  let profPath = "";
  if (opts.profile) profPath = opts.profile;
  else if (sourceRoot && exists(path.join(sourceRoot, "project-profile.json"))) profPath = path.join(sourceRoot, "project-profile.json");
  else if (exists(path.join(process.cwd(), "project-profile.json"))) profPath = path.join(process.cwd(), "project-profile.json");
  if (profPath && exists(profPath)) {
    try {
      const raw = JSON.parse(readUtf8(profPath).replace(/^\uFEFF/, ""));
      if (raw.webContentDir) prof.webContentDir = raw.webContentDir;
      if (raw.pathVariables) Object.assign(prof.pathVariables, raw.pathVariables);
      if (Array.isArray(raw.vendorPatterns)) prof.vendorPatterns = raw.vendorPatterns.concat(["resources/jqgrid/"]);
      if (Array.isArray(raw.appScriptHints)) prof.appScriptHints = raw.appScriptHints;
      if (Array.isArray(raw.ignoreAttrPatterns)) prof.ignoreAttrPatterns = raw.ignoreAttrPatterns;
      if (raw.jquery) Object.assign(prof.jquery, raw.jquery);
      if (raw.probe) Object.assign(prof.probe, raw.probe);
      if (Array.isArray(raw.learnedWrappers)) prof.learnedWrappers = prof.learnedWrappers.concat(raw.learnedWrappers);
      if (Array.isArray(raw.learnedFindings)) prof.learnedFindings = prof.learnedFindings.concat(raw.learnedFindings);
      if (Array.isArray(raw.sensitiveIdentifiers)) prof.sensitiveIdentifiers = raw.sensitiveIdentifiers;
      log("profile loaded: " + profPath);
    } catch (e) {
      warn("profile parse failed, using defaults: " + e.message);
    }
  }
  if (opts["jquery-version"]) {
    prof.jquery.targetVersion = opts["jquery-version"];
    prof.jquery.coreFile = "jquery-" + opts["jquery-version"] + ".min.js";
  }
  if (opts["migrate-version"]) {
    prof.jquery.migrateVersion = opts["migrate-version"];
    prof.jquery.migrateFile = "jquery-migrate-" + opts["migrate-version"] + ".min.js";
  }
  if (opts["migrate-trace"]) prof.jquery.migrateTrace = true;
  prof.appScriptHints = prof.appScriptHints.map(function (s) { return toPosix(s).toLowerCase(); });
  return prof;
}

const BOOL_FLAGS = { "audit-only": 1, "inject-probe": 1, "patch-jquery": 1, "migrate-trace": 1, "no-lab": 1, "self-test": 1, "include-snippets": 1, "warn-as-error": 1, "help": 1 };

function parseArgs(argv) {
  const opts = { _: [] };
  let i = 0;
  while (i < argv.length) {
    let a = argv[i];
    if (a.slice(0, 2) === "--") {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (key === "safe-packet") {
        if (next !== undefined && next.slice(0, 2) !== "--") { opts[key] = String(next).toLowerCase() !== "false"; i += 2; }
        else { opts[key] = true; i++; }
      } else if (BOOL_FLAGS[key]) {
        opts[key] = true; i++;
      } else if (next !== undefined && next.slice(0, 2) !== "--") {
        opts[key] = next; i += 2;
      } else {
        opts[key] = true; i++;
      }
    } else {
      opts._.push(a); i++;
    }
  }
  if (opts["safe-packet"] === undefined) opts["safe-packet"] = true;
  if (opts["max-packet-lines"] === undefined) opts["max-packet-lines"] = "400";
  return opts;
}

function helpText() {
  return [
    TOOL_NAME + " v" + TOOL_VERSION + " - jQuery " + CVE_ID + " remediation kit (offline, Node.js built-in only)",
    "",
    "Usage:",
    "  node run-jquery35-v5.js --source <dir> [--target <dir>] --report <dir> --mode <mode> [options]",
    "",
    "Modes:",
    "  plan          analyze only, write full report (no target write)",
    "  autofix       copy source to target, apply safe auto fixes, write report",
    "  patch-jquery  autofix + replace old jQuery core script tags with 3.x + Migrate",
    "  probe         autofix + generate runtime probe js + inject into layout jsp",
    "  lab           analyze + start local mock lab http server (--port, default 18080)",
    "  verify-clean  pre-release gate: fail on old jQuery / probe leftovers / criticals",
    "  pr-report     generate pr_description.md, bamboo_checklist.md, recommended_commits.txt",
    "  packet        analyze + write assistant_packet.txt / chat_summary.txt only",
    "  review-pack   analyze + write ai_review_pack.txt/json: a bounded, redacted",
    "                questionnaire over the most ambiguous/high-leverage code spots,",
    "                meant to be copy-pasted to an external AI and iterated on",
    "  self-test     build a sample project in temp dir and validate the tool end-to-end",
    "",
    "Options:",
    "  --source <dir>            project root or WebContent dir (auto-detected)",
    "  --target <dir>            TO-BE output dir (never writes into source)",
    "  --report <dir>            report output dir",
    "  --mode <mode>             see modes above (default: plan)",
    "  --port <n>                lab server port (default 18080)",
    "  --profile <file>          project-profile.json path (also carries learnedWrappers/",
    "                            learnedFindings from a previous review-pack round)",
    "  --jquery-version <v>      default " + DEFAULT_JQUERY_VERSION,
    "  --migrate-version <v>     default " + DEFAULT_MIGRATE_VERSION,
    "  --inject-probe            also inject probe in autofix/patch-jquery mode",
    "  --patch-jquery            also swap jQuery core in autofix mode",
    "  --migrate-trace           patch-jquery: insert jQuery.migrateTrace=true",
    "                            and migrateMute=false directly after Migrate",
    "  --audit-only              alias of --mode plan",
    "  --safe-packet [true|false]  exclude code snippets from assistant_packet (default true)",
    "  --include-snippets        include short snippets in packet (overrides safe-packet)",
    "  --max-packet-lines <n>    packet line cap (default 400)",
    "  --max-review-cases <n>    review-pack: max distinct cases per round (default 20)",
    "  --context-lines <n>       review-pack: excerpt lines shown before/after (default 1)",
    "  --max-review-lines <n>    review-pack: ai_review_pack.txt line cap (default 300)",
    "  --no-lab                  skip mock_routes.json / mock_data_default.json generation",
    "  --warn-as-error           verify-clean returns exit 1 on WARN",
    "  --help                    this help",
    ""
  ].join("\n");
}

function detectWebContent(sourceRoot, profile) {
  const cand1 = path.join(sourceRoot, profile.webContentDir);
  if (isDir(cand1) && isDir(path.join(cand1, "WEB-INF"))) return cand1;
  if (isDir(cand1)) return cand1;
  const own = ["WEB-INF", "js", "css", "resources"];
  let hit = 0;
  own.forEach(function (d) { if (isDir(path.join(sourceRoot, d))) hit++; });
  if (hit >= 1 && isDir(path.join(sourceRoot, "WEB-INF"))) return sourceRoot;
  if (hit >= 2) return sourceRoot;
  const names = isDir(sourceRoot) ? fs.readdirSync(sourceRoot) : [];
  for (let i = 0; i < names.length; i++) {
    const c = path.join(sourceRoot, names[i]);
    if (isDir(c) && isDir(path.join(c, "WEB-INF"))) return c;
  }
  return "";
}

function gitInfo(sourceRoot) {
  const info = { available: false, root: "", branch: "", changed: [], untracked: [] };
  try {
    const root = cp.execSync("git rev-parse --show-toplevel", { cwd: sourceRoot, stdio: ["ignore", "pipe", "ignore"], timeout: 8000 }).toString("utf8").trim();
    if (!root) return info;
    info.available = true;
    info.root = root;
    try { info.branch = cp.execSync("git rev-parse --abbrev-ref HEAD", { cwd: sourceRoot, stdio: ["ignore", "pipe", "ignore"], timeout: 8000 }).toString("utf8").trim(); } catch (e) { }
    try {
      const st = cp.execSync("git status --porcelain", { cwd: sourceRoot, stdio: ["ignore", "pipe", "ignore"], timeout: 15000 }).toString("utf8");
      st.split(/\r?\n/).forEach(function (ln) {
        if (!ln.trim()) return;
        const code = ln.slice(0, 2);
        const f = ln.slice(3).trim();
        if (code === "??") info.untracked.push(f); else info.changed.push(f);
      });
    } catch (e) { }
  } catch (e) { }
  return info;
}
function applyPathVars(ref, profile) {
  let out = String(ref);
  const keys = Object.keys(profile.pathVariables).sort(function (a, b) { return b.length - a.length; });
  keys.forEach(function (k) {
    while (out.indexOf(k) >= 0) out = out.split(k).join(profile.pathVariables[k]);
  });
  return out;
}

function normalizeWcPath(p) {
  const parts = toPosix(p).split("/");
  const out = [];
  for (let i = 0; i < parts.length; i++) {
    const seg = parts[i];
    if (seg === "" || seg === ".") continue;
    if (seg === "..") { out.pop(); continue; }
    out.push(seg);
  }
  return out.join("/");
}

function resolveRef(rawRef, pageRel, model) {
  const r = { raw: rawRef, resolved: "", exists: false, reason: "" };
  let ref = String(rawRef).trim();
  if (!ref) { r.reason = "empty"; return r; }
  if (/^(https?:)?\/\//i.test(ref)) { r.reason = "external-url"; r.resolved = ref; return r; }
  if (/^(javascript:|data:|#|mailto:)/i.test(ref)) { r.reason = "non-file"; return r; }
  ref = ref.split(/[?#]/)[0];
  let sub = applyPathVars(ref, model.profile);
  if (/<%[^%]*%>/.test(sub)) { r.reason = "jsp-expression"; r.resolved = sub; return r; }
  if (/\$\{[^}]*\}/.test(sub)) { r.reason = "unknown-el-variable"; r.resolved = sub; return r; }
  let wcRel;
  if (sub.charAt(0) === "/") wcRel = normalizeWcPath(sub);
  else wcRel = normalizeWcPath(toPosix(path.posix.dirname(toPosix(pageRel))) + "/" + sub);
  r.resolved = wcRel;
  if (model.fileIndex[wcRel.toLowerCase()]) { r.exists = true; }
  else r.reason = "file-not-found";
  return r;
}

function scriptSrcInfo(tag, tagStart) {
  const m = /\bsrc\s*=\s*(["'])([\s\S]*?)\1/i.exec(tag);
  if (!m) return null;
  const quoteAt = m[0].indexOf(m[1]);
  const srcStart = tagStart + m.index + quoteAt + 1;
  return { raw: m[2], srcStart: srcStart, srcEnd: srcStart + m[2].length };
}

function collectPageStructure(ctx) {
  const text = ctx.text;
  const refs = { scripts: [], css: [], includes: [], inlineRegions: [] };
  const scriptOpenRe = /<script\b[^>]*>/gi;
  let m;
  while ((m = scriptOpenRe.exec(text)) !== null) {
    const tag = m[0];
    const tagStart = m.index;
    const tagEnd = m.index + tag.length;
    const srcInfo = scriptSrcInfo(tag, tagStart);
    if (srcInfo) {
      refs.scripts.push({ raw: srcInfo.raw, idx: tagStart, tag: tag, tagEnd: tagEnd, srcStart: srcInfo.srcStart, srcEnd: srcInfo.srcEnd });
    } else {
      const closeIdx = text.toLowerCase().indexOf("</script", tagEnd);
      const end = closeIdx >= 0 ? closeIdx : text.length;
      const typeM = tag.match(/\btype\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
      const type = (typeM ? (typeM[1] || typeM[2] || "") : "").toLowerCase();
      const isJs = !type || type.indexOf("javascript") >= 0 || type === "module";
      if (isJs && end > tagEnd) refs.inlineRegions.push({ start: tagEnd, end: end });
      if (closeIdx >= 0) scriptOpenRe.lastIndex = closeIdx;
    }
  }
  const linkRe = /<link\b[^>]*>/gi;
  while ((m = linkRe.exec(text)) !== null) {
    const tag = m[0];
    const hrefM = tag.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
    if (!hrefM) continue;
    const href = hrefM[1] !== undefined ? hrefM[1] : hrefM[2];
    const isCss = /rel\s*=\s*["']?stylesheet/i.test(tag) || /\.css(\?|$)/i.test(href);
    if (isCss) refs.css.push({ raw: href, idx: m.index });
  }
  const incRes = [
    { re: /<%@\s*include\s+file\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, type: "static-include" },
    { re: /<jsp:include\s+page\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, type: "jsp-include" },
    { re: /<c:import\s+url\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, type: "c-import" }
  ];
  incRes.forEach(function (ir) {
    let mm;
    while ((mm = ir.re.exec(text)) !== null) {
      refs.includes.push({ raw: mm[1] !== undefined ? mm[1] : mm[2], idx: mm.index, type: ir.type });
    }
  });
  const tilesRe = /<tiles:(insert|insertAttribute|insertDefinition|insertTemplate)\b[^>]*>/gi;
  while ((m = tilesRe.exec(text)) !== null) {
    refs.includes.push({ raw: m[0].slice(0, 120), idx: m.index, type: "tiles", unresolvable: true });
  }
  return refs;
}

function scriptRefMeta(rawRef, resolved, model) {
  const name = fileNameOf(resolved && resolved.resolved ? resolved.resolved : rawRef);
  const lib = classifyLib(resolved && resolved.resolved ? resolved.resolved : rawRef, model.profile);
  let ver = versionFromName(name);
  const isCore = isJqueryCoreName(name);
  const isMig = isMigrateName(name);
  if (isCore && !ver && resolved && resolved.exists) {
    const abs = model.fileIndex[resolved.resolved.toLowerCase()];
    if (abs) ver = sniffJqueryVersion(abs);
  }
  const isOld = isCore && ver && versionLt(ver, TARGET_JQUERY_FLOOR_VERSION);
  return { name: name, lib: isCore ? "jquery-core" : lib, ver: ver, isCore: isCore, isMigrate: isMig, isOld: !!isOld };
}

function addFinding(model, ctx, o) {
  const f = {
    abs: ctx.abs,
    rel: ctx.rel,
    projRel: ctx.projRel,
    line: o.line || (o.idx !== undefined ? lineOf(ctx.lineStarts, o.idx) : 0),
    category: o.category,
    pattern: o.pattern || "",
    priority: o.priority,
    confidence: o.confidence || "Medium",
    action: o.action || "ReviewOnly",
    before: trunc(o.before || "", 220),
    after: trunc(o.after || "", 220),
    reason: trunc(o.reason || "", 300),
    lib: ctx.lib,
    thirdParty: ctx.isVendor ? "Y" : "N",
    commitGroup: o.commitGroup || "UNKNOWN",
    suggestion: o.suggestion || "",
    editStart: o.editStart,
    editEnd: o.editEnd,
    replacement: o.replacement,
    pending: o.pending || null,
    idx: o.idx
  };
  if (ctx.isVendor && f.priority !== "Critical") {
    if (f.action === "Changed") {
      f.action = "ReviewOnly";
      f.editStart = undefined; f.editEnd = undefined; f.replacement = undefined;
    }
    if (f.priority !== "Ignored") f.priority = "VendorReview";
    f.commitGroup = "VENDOR_REVIEW";
    f.pending = null;
  }
  ctx.findings.push(f);
  model.findings.push(f);
  return f;
}

function isSafeWrapperCall(masked, ctx) {
  const model = ctx && ctx.model;
  if (!model || !model.wrapperNames || model.wrapperNames.length === 0) return false;
  const t = masked.trim();
  for (let i = 0; i < model.wrapperNames.length; i++) {
    const name = model.wrapperNames[i];
    if (!model.safeWrapperNames[name]) continue;
    const m = t.match(new RegExp("^" + escapeRe(name) + "\\s*\\("));
    if (!m) continue;
    const openIdx = m[0].length - 1;
    const closeIdx = matchParen(t, openIdx);
    if (closeIdx === t.length - 1) return true;
  }
  return false;
}

function classifySinkArg(origArg, maskedArg, ctx) {
  const orig = origArg.trim();
  const masked = maskedArg;
  if (!orig) return { kind: "empty" };
  if (/\$\{[^}]*\}/.test(orig) || /<%=/.test(orig)) return { kind: "xss", why: "server-side EL/JSP expression concatenated into HTML" };
  if (isSafeWrapperCall(masked, ctx)) return { kind: "static", why: "wrapped by a learned safe helper function" };
  const ids = masked.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) || [];
  const realIds = ids.filter(function (x) { return !/^(true|false|null|undefined|new|function|this|typeof|var|let|const|return|if|else)$/.test(x); });
  if (realIds.length === 0) {
    if (/^[`'"]/.test(orig) || /^\(/.test(orig) || /^[+\s'"()`\[\]0-9.,-]*$/.test(masked.trim())) return { kind: "static" };
    return { kind: "static" };
  }
  for (let i = 0; i < realIds.length; i++) {
    if (ctx.taint && ctx.taint[realIds[i]]) return { kind: "xss", why: "argument uses ajax callback parameter '" + realIds[i] + "'" };
  }
  for (let i = 0; i < realIds.length; i++) {
    if (TAINT_NAMES[realIds[i].toLowerCase()]) return { kind: "xss", why: "identifier '" + realIds[i] + "' looks like server/business data" };
  }
  const hasConcat = /\+/.test(masked);
  const hasHtmlLiteral = /['"`][^'"`]*</.test(orig) || /<[a-zA-Z!\/]/.test(orig.replace(/['"`]/g, ""));
  if (hasConcat && (hasHtmlLiteral || /['"]/.test(orig))) return { kind: "xss", why: "string concatenation builds HTML with dynamic value" };
  const t = masked.trim();
  if (/^\$\s*\(/.test(t) || /^jQuery\s*\(/.test(t) || /^document\./.test(t) || t === "this" || /^\$[A-Za-z0-9_$]*$/.test(t)) {
    return { kind: "review", why: "DOM/jQuery object inserted, verify how it was built" };
  }
  return { kind: "review", why: "dynamic value of unknown origin: " + trunc(t, 60) };
}

const VOID_TAGS = Object.assign(Object.create(null), { area: 1, base: 1, br: 1, col: 1, embed: 1, hr: 1, img: 1, input: 1, link: 1, meta: 1, param: 1, source: 1, track: 1, wbr: 1 });
const SELF_CLOSED_RE = /<([a-zA-Z][a-zA-Z0-9-]*)\s*\/>/g;

function selfClosedHits(str) {
  const hits = [];
  SELF_CLOSED_RE.lastIndex = 0;
  let m;
  while ((m = SELF_CLOSED_RE.exec(str)) !== null) {
    if (!VOID_TAGS[m[1].toLowerCase()]) hits.push(m[1]);
  }
  return hits;
}

function expandSelfClosed(str) {
  return str.replace(SELF_CLOSED_RE, function (whole, tag) {
    return VOID_TAGS[tag.toLowerCase()] ? whole : "<" + tag + "></" + tag + ">";
  });
}

function checkSelfClosedArgs(model, ctx, absFn, args, methodLabel) {
  args.forEach(function (a) {
    const hits = selfClosedHits(a.orig);
    if (hits.length === 0) return;
    const inner = a.orig.replace(/^['"`]|['"`]$/g, "").trim();
    if (/^<[a-zA-Z][a-zA-Z0-9-]*\s*\/>$/.test(inner)) return;
    const ids = (a.masked.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) || []).filter(function (x) { return !/^(true|false|null|undefined)$/.test(x); });
    const pureLiteral = ids.length === 0 && /^["']/.test(a.orig) && !/`/.test(a.orig);
    if (pureLiteral) {
      addFinding(model, ctx, {
        idx: absFn(a.s), category: "self-closed-tag", pattern: methodLabel + " <" + hits[0] + "/>",
        priority: "AutoFixed", confidence: "High", action: "Changed",
        before: trunc(a.orig, 160), after: trunc(expandSelfClosed(a.orig), 160),
        reason: "jQuery 3.5 security fix (" + CVE_ID + ") stopped auto-expanding self-closed tags in HTML strings; explicit closing tags keep identical behavior on both old and new jQuery (Migrate does not restore this by default)",
        commitGroup: "AUTO_SAFE",
        editStart: absFn(a.s), editEnd: absFn(a.e), replacement: expandSelfClosed(a.rawOrig)
      });
    } else {
      addFinding(model, ctx, {
        idx: absFn(a.s), category: "self-closed-tag", pattern: methodLabel + " <" + hits[0] + "/>",
        priority: "Review", confidence: "Medium", action: "ReviewOnly",
        before: trunc(a.orig, 160),
        reason: "self-closed non-void tag <" + hits[0] + "/> inside dynamically built HTML: since jQuery 3.5 it is no longer expanded to <" + hits[0] + "></" + hits[0] + ">, so following siblings become children; rewrite with explicit closing tags",
        suggestion: "write <" + hits[0] + "></" + hits[0] + "> explicitly",
        commitGroup: "AUTO_SAFE"
      });
    }
  });
}

function collectTaint(ctx, masked, base) {
  const res = [
    /success\s*:\s*function\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)/g,
    /\.\s*(?:done|then|always|fail)\s*\(\s*function\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)/g,
    /\$\.(?:get|post|getJSON)\s*\([^()]{0,200}function\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)/g
  ];
  res.forEach(function (re) {
    let m;
    while ((m = re.exec(masked)) !== null) {
      const nm = m[1];
      if (nm && nm.length > 1) ctx.taint[nm] = true;
    }
  });
}

function collectWrapperTaint(model, ctx, masked, base) {
  if (!model.wrapperNames || model.wrapperNames.length === 0) return;
  model.wrapperNames.forEach(function (name) {
    const rule = model.wrapperRules[name];
    if (!rule || rule.role !== "ajaxSuccessJson") return;
    if (masked.indexOf(name) < 0) return;
    const re = rule.callRe;
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(masked)) !== null) {
      const parenIdx = m.index + m[0].length - 1;
      const closeIdx = matchParen(masked, parenIdx);
      if (closeIdx < 0) continue;
      const spans = splitTopArgs(masked, parenIdx + 1, closeIdx);
      const pIdx = typeof rule.calleeParamIndex === "number" ? rule.calleeParamIndex : spans.length - 1;
      if (pIdx < 0 || pIdx >= spans.length) continue;
      const argMasked = masked.slice(spans[pIdx].s, spans[pIdx].e).trim();
      const fm = argMasked.match(/^function\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)/);
      if (fm) ctx.taint[fm[1]] = true;
    }
  });
}

function collectDefs(model, ctx, masked, base) {
  const res = [
    /function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*\{/g,
    /([A-Za-z_$][A-Za-z0-9_$]*)\s*[:=]\s*function\s*\(([^)]*)\)\s*\{/g
  ];
  res.forEach(function (re, ri) {
    let m;
    while ((m = re.exec(masked)) !== null) {
      const name = m[1];
      const params = m[2].split(",").map(function (s) { return s.trim(); }).filter(Boolean);
      const braceLocal = masked.indexOf("{", m.index + m[0].length - 1);
      if (braceLocal < 0) continue;
      const endLocal = matchBrace(masked, braceLocal);
      if (endLocal < 0) continue;
      const def = {
        name: name, params: params, ctx: ctx,
        bodyStart: base + braceLocal, bodyEnd: base + endLocal,
        defIdx: base + m.index, form: ri === 0 ? "decl" : "assign"
      };
      if (!model.defs[name]) model.defs[name] = [];
      model.defs[name].push(def);
    }
  });
}

function premaskRegion(model, ctx, start, end) {
  const orig = ctx.text.slice(start, end);
  if (!orig.trim()) return null;
  const masked = maskJs(orig, false);
  const region = { start: start, end: end, masked: masked, orig: orig };
  ctx.regions.push(region);
  collectTaint(ctx, masked, start);
  collectWrapperTaint(model, ctx, masked, start);
  collectDefs(model, ctx, masked, start);
  return region;
}

function scanRegionFindings(model, ctx, region) {
  const orig = region.orig;
  const masked = region.masked;
  const start = region.start;
  const O = function (s, e) { return orig.slice(s, e); };
  const abs = function (i) { return start + i; };

  const callRe = /\.\s*(bind|unbind|delegate|undelegate|size|load|attr|removeAttr|success|error|complete|live|die|html|append|prepend|before|after|replaceWith|andSelf)\s*\(/g;
  let m;
  while ((m = callRe.exec(masked)) !== null) {
    const name = m[1];
    const dotIdx = m.index;
    const parenIdx = m.index + m[0].length - 1;
    const closeIdx = matchParen(masked, parenIdx);
    if (closeIdx < 0) continue;
    const argSpans = splitTopArgs(masked, parenIdx + 1, closeIdx);
    const args = argSpans.map(function (sp) {
      return { orig: O(sp.s, sp.e).trim(), rawOrig: O(sp.s, sp.e), masked: masked.slice(sp.s, sp.e).trim(), s: sp.s, e: sp.e };
    });
    const recv = receiverInfo(masked, orig, dotIdx);
    const jq = isJqReceiver(recv);
    const callText = trunc((recv.text ? recv.text : "") + O(dotIdx, closeIdx + 1), 200);
    const fIdx = abs(dotIdx);

    if (name === "bind" || name === "unbind") {
      if (recv.base === "}" ) continue;
      if (args.length >= 1 && (args[0].masked === "this" || /^this\s*,/.test(args[0].masked) || args[0].masked === "null")) continue;
      if (args.length === 0 && !jq && name === "bind") continue;
      const newName = name === "bind" ? "on" : "off";
      if (jq) {
        addFinding(model, ctx, {
          idx: fIdx, category: name + "-to-" + newName, pattern: "." + name + "(",
          priority: "AutoFixed", confidence: "High", action: "Changed",
          before: callText, after: "." + newName + "(...)",
          reason: "jQuery ." + name + "() deprecated, replaced with ." + newName + "()",
          commitGroup: "AUTO_SAFE",
          editStart: fIdx, editEnd: abs(parenIdx), replacement: "." + newName
        });
      } else {
        addFinding(model, ctx, {
          idx: fIdx, category: name + "-to-" + newName, pattern: "." + name + "(",
          priority: "Review", confidence: "Low", action: "ReviewOnly",
          before: callText,
          reason: "receiver '" + trunc(recv.base || recv.text, 40) + "' not confirmed as jQuery object; Function.prototype.bind must not be changed",
          suggestion: "if jQuery object: ." + newName + "(...)",
          commitGroup: "AUTO_SAFE"
        });
      }
      continue;
    }

    if (name === "delegate" || name === "undelegate") {
      const newName = name === "delegate" ? "on" : "off";
      if (jq && args.length === 3) {
        const rep = "." + newName + "(" + args[1].orig + ", " + args[0].orig + ", " + args[2].orig + ")";
        addFinding(model, ctx, {
          idx: fIdx, category: name + "-to-" + newName, pattern: "." + name + "(",
          priority: "AutoFixed", confidence: "High", action: "Changed",
          before: callText, after: rep,
          reason: "." + name + "(selector,event,handler) rewritten to ." + newName + "(event,selector,handler)",
          commitGroup: "AUTO_SAFE",
          editStart: fIdx, editEnd: abs(closeIdx) + 1, replacement: rep
        });
      } else {
        addFinding(model, ctx, {
          idx: fIdx, category: name + "-to-" + newName, pattern: "." + name + "(",
          priority: "Review", confidence: "Low", action: "ReviewOnly",
          before: callText,
          reason: args.length !== 3 ? "argument count " + args.length + " not a simple 3-arg pattern" : "receiver not confirmed as jQuery object",
          suggestion: "." + newName + "(event, selector, handler)",
          commitGroup: "AUTO_SAFE"
        });
      }
      continue;
    }

    if (name === "size") {
      if (args.length === 0 && jq) {
        addFinding(model, ctx, {
          idx: fIdx, category: "size-to-length", pattern: ".size()",
          priority: "AutoFixed", confidence: "High", action: "Changed",
          before: callText, after: ".length",
          reason: ".size() removed in jQuery 3.0",
          commitGroup: "AUTO_SAFE",
          editStart: fIdx, editEnd: abs(closeIdx) + 1, replacement: ".length"
        });
      } else if (args.length === 0) {
        addFinding(model, ctx, {
          idx: fIdx, category: "size-to-length", pattern: ".size()",
          priority: "Review", confidence: "Low", action: "ReviewOnly",
          before: callText, reason: "receiver not confirmed as jQuery object",
          suggestion: ".length", commitGroup: "AUTO_SAFE"
        });
      }
      continue;
    }

    if (name === "load") {
      if (isWindowJq(recv) && args.length >= 1 && !/^['"]/.test(args[0].masked)) {
        addFinding(model, ctx, {
          idx: fIdx, category: "event-shortcut-load", pattern: ".load(",
          priority: "AutoFixed", confidence: "High", action: "Changed",
          before: callText, after: '.on("load", ...)',
          reason: "window load event shortcut removed in jQuery 3.0",
          commitGroup: "AUTO_SAFE",
          editStart: fIdx, editEnd: abs(parenIdx) + 1, replacement: '.on("load", '
        });
      } else if (jq && args.length >= 1 && !/^['"]/.test(args[0].masked) && recv.base !== "$" && recv.base !== "jQuery") {
        addFinding(model, ctx, {
          idx: fIdx, category: "event-shortcut-load", pattern: ".load(",
          priority: "Review", confidence: "Low", action: "ReviewOnly",
          before: callText,
          reason: "possible load event shortcut (not AJAX .load(url)); verify receiver and handler",
          suggestion: '.on("load", handler)', commitGroup: "AUTO_SAFE"
        });
      }
      continue;
    }

    if (name === "attr" || name === "removeAttr") {
      handleAttr(model, ctx, { name: name, args: args, fIdx: fIdx, dotIdx: dotIdx, closeIdx: closeIdx, abs: abs, callText: callText, jq: jq, recv: recv });
      continue;
    }

    if (name === "success" || name === "error" || name === "complete") {
      if (SKIP_CALLBACK_BASES[recv.base]) continue;
      if (name === "error" && args.length === 0) continue;
      const rootTxt = String(recv.text || "");
      const ajaxCtx = /\$\.(ajax|get|post|getJSON)\s*\(/.test(rootTxt) || /\.(ajax|get|post|getJSON)\s*\(/.test(rootTxt) || /(xhr|jqxhr|ajax|req)/i.test(recv.base || "");
      const map = { success: "done", error: "fail", complete: "always" };
      let sugg, why;
      if (ajaxCtx) {
        sugg = "." + map[name] + "(...)";
        why = "jqXHR ." + name + "() removed in jQuery 3.0 (AJAX chain detected)";
      } else if (name === "error" && jq) {
        sugg = '.on("error", handler)';
        why = ".error() event shortcut removed in jQuery 3.0 (DOM element context)";
      } else {
        sugg = "AJAX: ." + map[name] + "(...) / DOM event: .on(\"" + name + "\", fn)";
        why = "." + name + "() shorthand removed in jQuery 3.0; context (AJAX vs DOM) must be confirmed";
      }
      addFinding(model, ctx, {
        idx: fIdx, category: "jqxhr-shorthand", pattern: "." + name + "(",
        priority: "Manual", confidence: ajaxCtx ? "High" : "Medium", action: "ReviewOnly",
        before: callText, reason: why, suggestion: sugg, commitGroup: "UNKNOWN"
      });
      continue;
    }

    if (name === "live" || name === "die") {
      const sugg = name === "live"
        ? '$(document).on(event, "SELECTOR", handler)'
        : '$(document).off(event, "SELECTOR", handler)';
      addFinding(model, ctx, {
        idx: fIdx, category: "live-die", pattern: "." + name + "(",
        priority: "Manual", confidence: "High", action: "ReviewOnly",
        before: callText,
        reason: "." + name + "() removed in jQuery 1.9; requires delegation rewrite",
        suggestion: sugg, commitGroup: "UNKNOWN"
      });
      continue;
    }

    if (name === "andSelf") {
      if (args.length === 0) {
        addFinding(model, ctx, {
          idx: fIdx, category: "andself-to-addback", pattern: ".andSelf()",
          priority: "AutoFixed", confidence: "High", action: "Changed",
          before: callText, after: ".addBack()",
          reason: ".andSelf() removed in jQuery 3.0",
          commitGroup: "AUTO_SAFE",
          editStart: fIdx, editEnd: abs(closeIdx) + 1, replacement: ".addBack()"
        });
      }
      continue;
    }

    if (name === "html" || name === "append" || name === "prepend" || name === "before" || name === "after" || name === "replaceWith") {
      if (args.length === 0) continue;
      if ((name === "before" || name === "after") && !jq && !recv.base) continue;
      checkSelfClosedArgs(model, ctx, abs, args, "." + name + "(");
      let worst = { kind: "static" };
      for (let ai = 0; ai < args.length; ai++) {
        const cls = classifySinkArg(args[ai].orig, args[ai].masked, ctx);
        if (cls.kind === "xss") { worst = cls; break; }
        if (cls.kind === "review" && worst.kind !== "xss") worst = cls;
        if (cls.kind === "static" && worst.kind === "static" && cls.why && !worst.why) worst = cls;
      }
      if (worst.kind === "empty") continue;
      if (worst.kind === "static") {
        addFinding(model, ctx, {
          idx: fIdx, category: "dom-sink", pattern: "." + name + "(static)",
          priority: "StaticHtmlLow", confidence: "High", action: "Ignored",
          before: callText,
          reason: worst.why || "static HTML literal only, no dynamic data",
          commitGroup: "STATIC_LOW"
        });
      } else if (worst.kind === "xss") {
        addFinding(model, ctx, {
          idx: fIdx, category: "dom-sink", pattern: "." + name + "(dynamic)",
          priority: "XssHigh", confidence: "High", action: "ReviewOnly",
          before: callText,
          reason: "DOM XSS candidate: " + worst.why,
          suggestion: "plain text: .text(value) / keep structure: escapeHtml(value) / server HTML: verify trust boundary or sanitize",
          commitGroup: "DOM_XSS"
        });
      } else {
        addFinding(model, ctx, {
          idx: fIdx, category: "dom-sink", pattern: "." + name + "(object)",
          priority: "Review", confidence: "Medium", action: "ReviewOnly",
          before: callText,
          reason: worst.why,
          suggestion: "confirm inserted content is built from trusted values; prefer .text() for data",
          commitGroup: "DOM_XSS"
        });
      }
      continue;
    }
  }

  if (model.wrapperNames && model.wrapperNames.length > 0) {
    model.wrapperNames.forEach(function (wname) {
      const rule = model.wrapperRules[wname];
      if (!rule || rule.role !== "domSinkArg") return;
      if (masked.indexOf(wname) < 0) return;
      const wrapRe = rule.callRe;
      wrapRe.lastIndex = 0;
      let wm;
      while ((wm = wrapRe.exec(masked)) !== null) {
        const wIdx = abs(wm.index + wm[1].length);
        const parenIdx = wm.index + wm[0].length - 1;
        const closeIdx = matchParen(masked, parenIdx);
        if (closeIdx < 0) continue;
        const spans = splitTopArgs(masked, parenIdx + 1, closeIdx);
        const pIdx = typeof rule.sinkParamIndex === "number" ? rule.sinkParamIndex : 0;
        if (pIdx < 0 || pIdx >= spans.length) continue;
        const argOrig = O(spans[pIdx].s, spans[pIdx].e).trim();
        const argMasked = masked.slice(spans[pIdx].s, spans[pIdx].e).trim();
        if (!argOrig) continue;
        const cls = classifySinkArg(argOrig, argMasked, ctx);
        const callText = trunc(wname + O(parenIdx, closeIdx + 1), 160);
        if (cls.kind === "xss") {
          addFinding(model, ctx, {
            idx: wIdx, category: "wrapper-dom-sink", pattern: wname + "(dynamic)",
            priority: "XssHigh", confidence: "Medium", action: "ReviewOnly",
            before: callText,
            reason: "learned wrapper '" + wname + "' treated as DOM HTML sink: " + (cls.why || ""),
            suggestion: "verify " + wname + "'s internal .html()/.append() usage; prefer .text() for data",
            commitGroup: "DOM_XSS"
          });
        } else if (cls.kind === "review") {
          addFinding(model, ctx, {
            idx: wIdx, category: "wrapper-dom-sink", pattern: wname + "(object)",
            priority: "Review", confidence: "Low", action: "ReviewOnly",
            before: callText,
            reason: "learned wrapper '" + wname + "' DOM sink argument: " + (cls.why || ""),
            commitGroup: "DOM_XSS"
          });
        }
      }
    });
  }

  const utilRe = /(\$|jQuery)\s*\.\s*(trim|parseHTML|browser)\b/g;
  while ((m = utilRe.exec(masked)) !== null) {
    const util = m[2];
    const fIdx = abs(m.index);
    if (util === "browser") {
      addFinding(model, ctx, {
        idx: fIdx, category: "jquery-browser", pattern: "$.browser",
        priority: "Manual", confidence: "High", action: "ReviewOnly",
        before: trunc(O(m.index, Math.min(m.index + 80, orig.length)), 100),
        reason: "$.browser removed in jQuery 1.9; likely dead or migrate-dependent code",
        suggestion: "feature detection or navigator.userAgent check",
        commitGroup: "UNKNOWN"
      });
      continue;
    }
    const parenIdx = masked.indexOf("(", m.index + m[0].length);
    if (parenIdx < 0 || masked.slice(m.index + m[0].length, parenIdx).trim() !== "") continue;
    const closeIdx = matchParen(masked, parenIdx);
    if (closeIdx < 0) continue;
    const argOrig = O(parenIdx + 1, closeIdx).trim();
    const argMasked = masked.slice(parenIdx + 1, closeIdx).trim();
    if (util === "trim") {
      addFinding(model, ctx, {
        idx: fIdx, category: "trim-deprecated", pattern: "$.trim(",
        priority: "StaticHtmlLow", confidence: "High", action: "Ignored",
        before: trunc(O(m.index, closeIdx + 1), 120),
        reason: "$.trim is still supported on jQuery 3.x; defer until a future jQuery 4 cleanup because native trim has different null/undefined behavior",
        suggestion: "Leave unchanged for the 3.5.1 landing; later replace only after confirming null/undefined inputs",
        commitGroup: "DEFERRED_4X"
      });
    } else if (util === "parseHTML") {
      checkSelfClosedArgs(model, ctx, abs, [{ orig: argOrig, rawOrig: O(parenIdx + 1, closeIdx), masked: argMasked, s: parenIdx + 1, e: closeIdx }], "$.parseHTML(");
      const cls = classifySinkArg(argOrig, argMasked, ctx);
      if (cls.kind === "static") {
        addFinding(model, ctx, {
          idx: fIdx, category: "parse-html", pattern: "$.parseHTML(static)",
          priority: "StaticHtmlLow", confidence: "High", action: "Ignored",
          before: trunc(O(m.index, closeIdx + 1), 120),
          reason: cls.why || "static HTML literal", commitGroup: "STATIC_LOW"
        });
      } else {
        addFinding(model, ctx, {
          idx: fIdx, category: "parse-html", pattern: "$.parseHTML(dynamic)",
          priority: cls.kind === "xss" ? "XssHigh" : "Review",
          confidence: "Medium", action: "ReviewOnly",
          before: trunc(O(m.index, closeIdx + 1), 120),
          reason: "parseHTML with dynamic input: " + (cls.why || ""),
          suggestion: "verify input source; consider sanitizer",
          commitGroup: "DOM_XSS"
        });
      }
    }
  }

  const factoryRe = /(^|[^\w$.])(\$|jQuery)\s*\(/g;
  while ((m = factoryRe.exec(masked)) !== null) {
    const parenIdx = m.index + m[0].length - 1;
    const closeIdx = matchParen(masked, parenIdx);
    if (closeIdx < 0) continue;
    const spans = splitTopArgs(masked, parenIdx + 1, closeIdx);
    if (spans.length === 0) continue;
    const a0o = O(spans[0].s, spans[0].e).trim();
    const a0m = masked.slice(spans[0].s, spans[0].e).trim();
    if (!/^['"`]/.test(a0o) && !/\+/.test(a0m)) continue;
    const inner = a0o.replace(/^['"`]|['"`]$/g, "");
    if (!/^\s*</.test(inner) && !/['"`]\s*</.test(a0o)) continue;
    const fIdx = abs(m.index + m[0].length - (m[2] === "$" ? 2 : 7) - 0);
    checkSelfClosedArgs(model, ctx, abs, [{ orig: a0o, rawOrig: O(spans[0].s, spans[0].e), masked: a0m, s: spans[0].s, e: spans[0].e }], "$(");
    const cls = classifySinkArg(a0o, a0m, ctx);
    if (cls.kind === "static") {
      addFinding(model, ctx, {
        idx: abs(parenIdx), category: "dom-factory", pattern: "$(static html)",
        priority: "StaticHtmlLow", confidence: "High", action: "Ignored",
        before: trunc("$(" + a0o + ")", 120),
        reason: cls.why || "static DOM factory literal", commitGroup: "STATIC_LOW"
      });
    } else if (cls.kind === "xss") {
      addFinding(model, ctx, {
        idx: abs(parenIdx), category: "dom-factory", pattern: "$(dynamic html)",
        priority: "XssHigh", confidence: "High", action: "ReviewOnly",
        before: trunc("$(" + a0o + ")", 160),
        reason: "DOM factory with dynamic HTML: " + (cls.why || ""),
        suggestion: "build element then set data via .text()/.val()/.attr()",
        commitGroup: "DOM_XSS"
      });
    }
  }
}

function handleAttr(model, ctx, p) {
  const args = p.args;
  const nameArgM = args.length >= 1 ? args[0].masked : "";
  const nameArgO = args.length >= 1 ? args[0].orig : "";
  const litM = nameArgO.match(/^["']([A-Za-z-]+)["']$/);
  if (p.name === "removeAttr") {
    if (!litM) return;
    const an = litM[1].toLowerCase();
    if (an.indexOf("aria-") === 0) {
      addFinding(model, ctx, {
        idx: p.fIdx, category: "aria-attr", pattern: '.removeAttr("' + an + '")',
        priority: "Ignored", confidence: "High", action: "Ignored",
        before: p.callText, reason: "aria-* attributes stay as attributes; do not convert to prop",
        commitGroup: "UNKNOWN"
      });
      return;
    }
    if (!BOOL_ATTRS[an]) return;
    const rep = '.prop("' + an + '", false)';
    addFinding(model, ctx, {
      idx: p.fIdx, category: "bool-attr-removeattr", pattern: '.removeAttr("' + an + '")',
      priority: "AutoFixed", confidence: "High", action: "Changed",
      before: p.callText, after: rep,
      reason: "boolean attribute removal converted to .prop(name, false) for jQuery 3.x consistency",
      commitGroup: "AUTO_SAFE",
      editStart: p.fIdx, editEnd: p.abs(p.closeIdx) + 1, replacement: rep
    });
    return;
  }
  if (args.length === 1 && /^\{/.test(nameArgM)) {
    if (/["']?(disabled|readonly|checked|selected)["']?\s*:/.test(nameArgO)) {
      addFinding(model, ctx, {
        idx: p.fIdx, category: "attr-object-form", pattern: ".attr({...})",
        priority: "Review", confidence: "Medium", action: "ReviewOnly",
        before: p.callText,
        reason: "object-form .attr() contains boolean attribute keys; split boolean keys into .prop()",
        suggestion: "move disabled/readonly/checked/selected keys to .prop()",
        commitGroup: "MANUAL_BOOL_ATTR"
      });
    }
    return;
  }
  if (args.length !== 2 || !litM) return;
  const an = litM[1].toLowerCase();
  if (an.indexOf("aria-") === 0) return;
  if (!BOOL_ATTRS[an]) return;
  const vO = args[1].orig;
  const vM = args[1].masked;
  const mkProp = function (valExpr) { return '.prop("' + an + '", ' + valExpr + ")"; };
  const autoEdit = function (valExpr, why, prio) {
    addFinding(model, ctx, {
      idx: p.fIdx, category: prio === "AutoFixed2" ? "bool-attr-variable" : "bool-attr-literal",
      pattern: '.attr("' + an + '", ...)',
      priority: prio || "AutoFixed", confidence: "High", action: "Changed",
      before: p.callText, after: mkProp(valExpr),
      reason: why, commitGroup: "AUTO_SAFE",
      editStart: p.fIdx, editEnd: p.abs(p.closeIdx) + 1, replacement: mkProp(valExpr)
    });
  };
  if (/^(true|false)$/.test(vM)) { autoEdit(vM, "boolean literal moved from attr to prop"); return; }
  const strLit = vO.match(/^["']([^"']*)["']$/);
  if (strLit) {
    const sv = strLit[1].toLowerCase();
    if (sv === an || sv === "true") { autoEdit("true", 'string value "' + strLit[1] + '" means enabled; converted to prop true'); return; }
    if (sv === "false") {
      addFinding(model, ctx, {
        idx: p.fIdx, category: "bool-attr-literal", pattern: '.attr("' + an + '", "false")',
        priority: "Manual", confidence: "Medium", action: "ReviewOnly",
        before: p.callText,
        reason: 'attr("' + an + '","false") actually ENABLED the attribute in old jQuery (any non-empty value); converting to prop false would flip runtime behavior - confirm original intent first',
        suggestion: mkProp("false") + " only if the intent was to clear " + an + ", otherwise " + mkProp("true"),
        commitGroup: "MANUAL_BOOL_ATTR"
      });
      return;
    }
    addFinding(model, ctx, {
      idx: p.fIdx, category: "bool-attr-literal", pattern: '.attr("' + an + '", "' + trunc(strLit[1], 20) + '")',
      priority: "Manual", confidence: "Medium", action: "ReviewOnly",
      before: p.callText,
      reason: 'string value "' + strLit[1] + '" is ambiguous for boolean attribute (any non-empty attr value enables it)',
      suggestion: mkProp("/* intended boolean */"),
      commitGroup: "MANUAL_BOOL_ATTR"
    });
    return;
  }
  if (/^[01]$/.test(vM)) { autoEdit(vM === "1" ? "true" : "false", "numeric 0/1 literal converted to boolean prop"); return; }
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(vM)) {
    addFinding(model, ctx, {
      idx: p.fIdx, category: "bool-attr-variable", pattern: '.attr("' + an + '", ' + vM + ")",
      priority: "Manual", confidence: "Medium", action: "ReviewOnly",
      before: p.callText,
      reason: "variable value; callsite type inference pending",
      suggestion: mkProp(vM + " /* verify type */"),
      commitGroup: "MANUAL_BOOL_ATTR",
      pending: { type: "boolattr-infer", attrName: an, ident: vM, editStart: p.fIdx, editEnd: p.abs(p.closeIdx) + 1 }
    });
    return;
  }
  if (/(===|!==|==|!=|>=|<=)/.test(vM) || /^!/.test(vM.trim())) {
    autoEdit(vO.trim(), "comparison expression always yields boolean; safe to move to prop");
    return;
  }
  addFinding(model, ctx, {
    idx: p.fIdx, category: "bool-attr-variable", pattern: '.attr("' + an + '", expr)',
    priority: "Manual", confidence: "Low", action: "ReviewOnly",
    before: p.callText,
    reason: "complex expression; truthiness differs between attr and prop (e.g. \"N\" and \"false\" strings are truthy)",
    suggestion: mkProp("Boolean(" + trunc(vO.trim(), 40) + ") /* map Y/N explicitly */"),
    commitGroup: "MANUAL_BOOL_ATTR"
  });
}

function literalGroupOf(argMasked, argOrig) {
  const t = String(argOrig).trim();
  if (/^(true|false)$/.test(t)) return { group: "bool", value: t };
  if (/^["']Y["']$/.test(t)) return { group: "yn", value: "Y" };
  if (/^["']N["']$/.test(t)) return { group: "yn", value: "N" };
  if (/^["']true["']$/.test(t)) return { group: "strtf", value: "true" };
  if (/^["']false["']$/.test(t)) return { group: "strtf", value: "false" };
  if (/^[01]$/.test(t)) return { group: "num01", value: t };
  if (/^["'][01]["']$/.test(t)) return { group: "str01", value: t.replace(/["']/g, "") };
  return null;
}

function resolveAutoFixed2(model) {
  const pend = model.findings.filter(function (f) { return f.pending && f.pending.type === "boolattr-infer"; });
  pend.forEach(function (f) {
    const ident = f.pending.ident;
    const ctx = model.ctxByRel[f.rel];
    let encl = null;
    const idx = f.pending.editStart;
    Object.keys(model.defs).forEach(function (nm) {
      model.defs[nm].forEach(function (d) {
        if (d.ctx !== ctx) return;
        if (idx <= d.bodyStart || idx >= d.bodyEnd) return;
        if (d.params.indexOf(ident) < 0) return;
        if (!encl || d.bodyStart > encl.bodyStart) encl = d;
      });
    });
    const finalize = function (ok, why, expr, sites) {
      if (ok) {
        f.priority = "AutoFixed2";
        f.action = "Changed";
        f.confidence = "High";
        f.after = '.prop("' + f.pending.attrName + '", ' + expr + ")";
        f.reason = trunc("callsite inference: " + why, 300);
        f.commitGroup = "AUTO_SAFE";
        f.editStart = f.pending.editStart;
        f.editEnd = f.pending.editEnd;
        f.replacement = '.prop("' + f.pending.attrName + '", ' + expr + ")";
      } else {
        f.priority = "Manual";
        f.action = "ReviewOnly";
        f.reason = trunc("AutoFixed2 not possible: " + why, 300);
        f.suggestion = '.prop("' + f.pending.attrName + '", ' + ident + ' === "Y") /* adjust comparison to actual callsite values */';
      }
      f.pending = null;
    };
    if (!encl) { finalize(false, "'" + ident + "' is not a parameter of an enclosing named function", null); return; }
    const defsForName = model.defs[encl.name] || [];
    if (defsForName.length !== 1) { finalize(false, "function '" + encl.name + "' defined " + defsForName.length + " times in project", null); return; }
    const pIdx = encl.params.indexOf(ident);
    const callRe = new RegExp("(^|[^A-Za-z0-9_$.])" + escapeRe(encl.name) + "\\s*\\(", "g");
    const sites = [];
    let ambiguous = "";
    model.textFiles.forEach(function (c2) {
      c2.regions.forEach(function (rg) {
        let mm;
        callRe.lastIndex = 0;
        while ((mm = callRe.exec(rg.masked)) !== null) {
          const nameStart = mm.index + mm[1].length;
          const before7 = rg.masked.slice(Math.max(0, nameStart - 12), nameStart);
          if (/function\s*$/.test(before7)) continue;
          const absIdx = rg.start + nameStart;
          if (c2 === encl.ctx && absIdx === encl.defIdx) continue;
          const prevCh = mm[1];
          if (prevCh === ".") { ambiguous = "method-style callsite ." + encl.name + "( found at " + c2.rel; return; }
          const openLocal = rg.masked.indexOf("(", nameStart);
          if (openLocal < 0) continue;
          const closeLocal = matchParen(rg.masked, openLocal);
          if (closeLocal < 0) continue;
          const spans = splitTopArgs(rg.masked, openLocal + 1, closeLocal);
          if (spans.length <= pIdx) { sites.push({ ctx: c2, idx: rg.start + nameStart, group: null, value: "(missing arg)" }); continue; }
          const aO = c2.text.slice(rg.start + spans[pIdx].s, rg.start + spans[pIdx].e).trim();
          const g = literalGroupOf(null, aO);
          sites.push({ ctx: c2, idx: rg.start + nameStart, group: g ? g.group : null, value: aO });
        }
      });
    });
    if (ambiguous) { finalize(false, ambiguous, null); return; }
    const realSites = sites;
    if (realSites.length === 0) { finalize(false, "no callsite found for '" + encl.name + "'", null); return; }
    const groups = uniq(realSites.map(function (s) { return s.group || "nonliteral"; }));
    const sampleTxt = realSites.slice(0, 3).map(function (s) {
      return s.ctx.rel + ":" + lineOf(s.ctx.lineStarts, s.idx) + "=" + trunc(s.value, 20);
    }).join(" | ");
    if (groups.length !== 1 || groups[0] === "nonliteral") {
      finalize(false, "callsite values not a single literal type group [" + groups.join(",") + "] samples: " + sampleTxt, null);
      return;
    }
    const g = groups[0];
    let expr = null;
    if (g === "bool") expr = ident;
    else if (g === "yn") expr = ident + ' === "Y"';
    else if (g === "strtf") expr = ident + ' === "true"';
    else if (g === "num01") expr = ident + " === 1";
    else if (g === "str01") expr = ident + ' === "1"';
    if (!expr) { finalize(false, "unsupported literal group " + g, null); return; }
    finalize(true, realSites.length + " callsite(s), all '" + g + "' type. samples: " + sampleTxt, expr, realSites);
  });
}
function buildModel(opts, mode) {
  if (!opts.source) throw new Error("--source is required for mode " + mode);
  const sourceRoot = path.resolve(opts.source);
  if (!isDir(sourceRoot)) throw new Error("source directory not found: " + sourceRoot);
  const profile = loadProfile(opts, sourceRoot);
  const webContentRoot = detectWebContent(sourceRoot, profile);
  if (!webContentRoot) throw new Error("WebContent could not be detected under: " + sourceRoot + " (expected <source>/WebContent or <source> containing WEB-INF)");
  const targetRoot = opts.target ? path.resolve(opts.target) : "";
  const reportRoot = opts.report ? path.resolve(opts.report) : "";
  if (targetRoot) {
    if (path.resolve(targetRoot).toLowerCase() === sourceRoot.toLowerCase()) throw new Error("target must not be the same as source (source is never modified)");
  }
  const model = {
    opts: opts, mode: mode, profile: profile,
    sourceRoot: sourceRoot, webContentRoot: webContentRoot,
    targetRoot: targetRoot, reportRoot: reportRoot,
    targetWcRoot: targetRoot ? path.join(targetRoot, path.relative(sourceRoot, webContentRoot)) : "",
    allFiles: [], textFiles: [], ctxByRel: Object.create(null), fileIndex: Object.create(null),
    findings: [], defs: Object.create(null), pages: [],
    pageScriptRows: [], pageCssRows: [], includeRows: [], unresolvedRows: [],
    effectiveRows: [], oldCoreRefs: [], jqueryLoadRows: [],
    ajaxRows: [], syntaxRows: [], probeInjections: [], patchResults: [],
    changed: {}, editWarnings: [], git: null, counters: {}, focus: [],
    scriptInv: [], pluginInv: [], dirInv: [], completeRows: [], needsRows: [],
    wrapperRules: Object.create(null), wrapperNames: [], safeWrapperNames: Object.create(null),
    learnedFindingsMap: Object.create(null), reviewCases: [], reviewCasesAll: 0, reviewRound: 1
  };
  if (targetRoot && isUnderDir(targetRoot, sourceRoot)) warn("target is inside source; it will be excluded from scan");
  if (reportRoot && isUnderDir(reportRoot, sourceRoot)) warn("report is inside source; it will be excluded from scan");
  return model;
}

function analyze(model) {
  buildWrapperRules(model);
  buildLearnedFindingsMap(model);
  const excl = [];
  if (model.targetRoot) excl.push(model.targetRoot);
  if (model.reportRoot) excl.push(model.reportRoot);
  log("scanning WebContent: " + model.webContentRoot);
  const files = walkFiles(model.webContentRoot, excl);
  files.forEach(function (f) {
    const rel = toPosix(path.relative(model.webContentRoot, f.abs));
    model.allFiles.push({ abs: f.abs, rel: rel, size: f.size, ext: path.extname(rel).toLowerCase() });
    model.fileIndex[rel.toLowerCase()] = f.abs;
  });
  log("files under WebContent: " + model.allFiles.length);
  model.allFiles.forEach(function (f) {
    if (TEXT_EXTS.indexOf(f.ext) < 0) return;
    if (f.size > 2 * 1024 * 1024) { warn("skip large file (>2MB): " + f.rel); return; }
    let text;
    try { text = readLatin1(f.abs); } catch (e) { warn("read failed: " + f.rel); return; }
    if (text.indexOf("\u0000") >= 0) { warn("binary-like file skipped: " + f.rel); return; }
    const lib = classifyLib(f.rel, model.profile);
    const ctx = {
      abs: f.abs, rel: f.rel,
      projRel: toPosix(path.relative(model.sourceRoot, f.abs)),
      ext: f.ext, size: f.size,
      isPage: PAGE_EXTS.indexOf(f.ext) >= 0,
      isJs: f.ext === ".js", isCss: f.ext === ".css",
      text: text, lineStarts: lineStartsOf(text), eol: detectEol(text),
      lib: lib, isVendor: lib !== "app" && lib !== "probe",
      isMin: isMinifiedFile(f.rel, text),
      findings: [], edits: [], regions: [], taint: Object.create(null), refs: null,
      model: model
    };
    if (ctx.isMin && !ctx.isVendor) ctx.isVendor = true;
    model.textFiles.push(ctx);
    model.ctxByRel[ctx.rel] = ctx;
  });
  log("text files to analyze: " + model.textFiles.length);
  let done = 0;
  model.textFiles.forEach(function (ctx) {
    if (ctx.isPage) {
      ctx.refs = collectPageStructure(ctx);
      const regions = ctx.refs.inlineRegions.map(function (rg) { return premaskRegion(model, ctx, rg.start, rg.end); }).filter(Boolean);
      regions.forEach(function (region) { scanRegionFindings(model, ctx, region); });
    } else if (ctx.isJs) {
      const region = premaskRegion(model, ctx, 0, ctx.text.length);
      if (region) scanRegionFindings(model, ctx, region);
    }
    done++;
    if (done % 100 === 0) log("scanned " + done + "/" + model.textFiles.length);
  });
  resolveAutoFixed2(model);
  annotateGroupKeys(model);
  applyLearnedFindingsOverrides(model);
  analyzePages(model);
  analyzeAjax(model);
  analyzeSyntax(model);
  buildInventories(model);
  dedupFindings(model);
  buildQueues(model);
  buildReviewCases(model);
  model.git = gitInfo(model.sourceRoot);
  summarize(model);
}

function buildWrapperRules(model) {
  const rules = Object.create(null);
  const safe = Object.create(null);
  const names = [];
  (model.profile.learnedWrappers || []).forEach(function (w) {
    if (!w || !w.name) return;
    const prev = rules[w.name];
    const rule = {
      name: w.name,
      role: w.role || "unknown",
      calleeParamIndex: typeof w.calleeParamIndex === "number" ? w.calleeParamIndex : null,
      sinkParamIndex: typeof w.sinkParamIndex === "number" ? w.sinkParamIndex : 0,
      notes: w.notes || "",
      callRe: new RegExp("(^|[^A-Za-z0-9_$.])" + escapeRe(w.name) + "\\s*\\(", "g")
    };
    if (prev && prev.role !== rule.role) {
      warn("learnedWrappers: '" + w.name + "' role changed " + prev.role + " -> " + rule.role + " (later entry in project-profile.json wins)");
    }
    rules[w.name] = rule;
    if (names.indexOf(w.name) < 0) names.push(w.name);
    safe[w.name] = rule.role === "safeWrapper";
  });
  model.wrapperRules = rules;
  model.wrapperNames = names;
  model.safeWrapperNames = safe;
}

function buildLearnedFindingsMap(model) {
  const map = Object.create(null);
  (model.profile.learnedFindings || []).forEach(function (e) {
    if (!e || !e.caseId) return;
    map[e.caseId] = e;
  });
  model.learnedFindingsMap = map;
}

function caseIdOf(kind, name) {
  let h1 = 0, h2 = 0;
  const s = kind + ":" + name;
  for (let i = 0; i < s.length; i++) {
    h1 = (h1 * 31 + s.charCodeAt(i)) >>> 0;
    h2 = (h2 * 131 + s.charCodeAt(i) + 7) >>> 0;
  }
  return kind + "-" + h1.toString(36).padStart(7, "0") + h2.toString(36).padStart(7, "0");
}

function findEnclosingDefName(model, f) {
  if (f.idx === undefined || f.idx === null) return null;
  const ctx = model.ctxByRel[f.rel];
  if (!ctx) return null;
  let best = null;
  Object.keys(model.defs).forEach(function (nm) {
    model.defs[nm].forEach(function (d) {
      if (d.ctx !== ctx) return;
      if (f.idx <= d.bodyStart || f.idx >= d.bodyEnd) return;
      if (!best || d.bodyStart > best.bodyStart) best = d;
    });
  });
  return best ? best.name : null;
}

function annotateGroupKeys(model) {
  model.findings.forEach(function (f) {
    if (f._caseId) return;
    const encl = findEnclosingDefName(model, f);
    f._groupKind = encl ? "FN" : "PT";
    f._groupName = encl || (f.category + "@" + f.rel);
    f._caseId = caseIdOf(f._groupKind, f._groupName);
  });
}

const LEARNED_DECISION_MAP = {
  "xss-high": { priority: "XssHigh", action: "ReviewOnly" },
  "manual": { priority: "Manual", action: "ReviewOnly" },
  "review": { priority: "Review", action: "ReviewOnly" },
  "static-safe": { priority: "StaticHtmlLow", action: "Ignored" },
  "vendor-review": { priority: "VendorReview", action: "ReviewOnly" },
  "ignored": { priority: "Ignored", action: "Ignored" }
};

function applyLearnedFindingsOverrides(model) {
  if (!model.learnedFindingsMap || Object.keys(model.learnedFindingsMap).length === 0) return;
  const warnedCaseIds = Object.create(null);
  model.findings.forEach(function (f) {
    if (f.thirdParty === "Y") return;
    if (f.action === "Changed") return;
    const entry = model.learnedFindingsMap[f._caseId];
    if (!entry || !entry.decision) return;
    if (entry.name && entry.name !== f._groupName) {
      if (!warnedCaseIds[f._caseId]) {
        warnedCaseIds[f._caseId] = true;
        warn("learnedFindings caseId " + f._caseId + " expected name '" + entry.name + "' but matched '" + f._groupName + "'; skipped as a precaution (possible hash mismatch or stale answer)");
      }
      return;
    }
    const dec = LEARNED_DECISION_MAP[entry.decision];
    if (!dec) return;
    f.priority = dec.priority;
    f.action = dec.action;
    f.reason = trunc("[learned:" + entry.decision + "] " + (entry.notes || "") + " | " + f.reason, 300);
  });
}

function analyzePages(model) {
  const pageCtxs = model.textFiles.filter(function (c) { return c.isPage; });
  const eventsByPage = {};
  pageCtxs.forEach(function (ctx) {
    const refs = ctx.refs || { scripts: [], css: [], includes: [], inlineRegions: [] };
    const events = [];
    refs.scripts.forEach(function (s) {
      const r = resolveRef(s.raw, ctx.rel, model);
      const meta = scriptRefMeta(s.raw, r, model);
      const line = lineOf(ctx.lineStarts, s.idx);
      const row = {
        page: ctx.rel, line: line, raw: s.raw, resolved: r.resolved, exists: r.exists,
        reason: r.reason, meta: meta, tag: s.tag, tagStart: s.idx, tagEnd: s.tagEnd,
        srcStart: s.srcStart, srcEnd: s.srcEnd, ctx: ctx
      };
      model.pageScriptRows.push(row);
      events.push({ idx: s.idx, kind: "script", row: row });
      if (meta.isCore || meta.isMigrate) model.jqueryLoadRows.push(row);
      if (meta.isOld) {
        model.oldCoreRefs.push(row);
        addFinding(model, ctx, {
          idx: s.idx, category: "jquery-core-old", pattern: "script src jquery " + meta.ver,
          priority: "Critical", confidence: "High", action: "CriticalOnly",
          before: trunc(lineTextAt(ctx.text, ctx.lineStarts, line).trim(), 200),
          reason: "jQuery core " + meta.ver + " < " + TARGET_JQUERY_FLOOR_VERSION + " (" + CVE_ID + "); replaced only in patch-jquery mode",
          suggestion: "replace with " + model.profile.jquery.coreFile + " + " + model.profile.jquery.migrateFile,
          commitGroup: "JQUERY_CORE"
        });
      } else if (meta.isCore && !meta.ver) {
        addFinding(model, ctx, {
          idx: s.idx, category: "jquery-core-unknown", pattern: "script src " + trunc(s.raw, 60),
          priority: "Review", confidence: "Low", action: "ReviewOnly",
          before: trunc(lineTextAt(ctx.text, ctx.lineStarts, line).trim(), 200),
          reason: "jQuery core reference with unknown version; verify it is " + TARGET_JQUERY_FLOOR_VERSION + " or higher",
          commitGroup: "JQUERY_CORE"
        });
      }
      if (!r.exists && r.reason !== "external-url" && r.reason !== "non-file") {
        model.unresolvedRows.push({ page: ctx.rel, type: "script", raw: s.raw, reason: r.reason });
      }
    });
    refs.css.forEach(function (s) {
      const r = resolveRef(s.raw, ctx.rel, model);
      const line = lineOf(ctx.lineStarts, s.idx);
      model.pageCssRows.push({
        page: ctx.rel, line: line, raw: s.raw, resolved: r.resolved, exists: r.exists,
        lib: classifyLib(r.resolved || s.raw, model.profile), ver: versionFromName(fileNameOf(s.raw))
      });
      if (!r.exists && r.reason !== "external-url" && r.reason !== "non-file") {
        model.unresolvedRows.push({ page: ctx.rel, type: "css", raw: s.raw, reason: r.reason });
      }
    });
    refs.includes.forEach(function (inc) {
      let resolved = "", ok = false, reason = "";
      if (inc.unresolvable) { reason = "tiles-heuristic-unresolved"; }
      else {
        const r = resolveRef(inc.raw, ctx.rel, model);
        resolved = r.resolved; ok = r.exists; reason = r.reason;
      }
      model.includeRows.push({ page: ctx.rel, type: inc.type, raw: inc.raw, resolved: resolved, ok: ok, reason: reason });
      if (!inc.unresolvable && ok) events.push({ idx: inc.idx, kind: "include", target: resolved });
      if (!ok) model.unresolvedRows.push({ page: ctx.rel, type: inc.type, raw: trunc(inc.raw, 120), reason: reason || "unresolved" });
    });
    events.sort(function (a, b) { return a.idx - b.idx; });
    eventsByPage[ctx.rel] = events;
  });

  const memo = {};
  function effectiveOf(rel, stack) {
    if (memo[rel]) return memo[rel];
    if (stack[rel]) return [];
    stack[rel] = true;
    const out = [];
    const evs = eventsByPage[rel] || [];
    evs.forEach(function (ev) {
      if (ev.kind === "script") {
        out.push({ row: ev.row, srcPage: rel });
      } else {
        const realRel = model.fileIndex[ev.target.toLowerCase()] ? findCtxRel(model, ev.target) : null;
        if (realRel) {
          effectiveOf(realRel, stack).forEach(function (e) { out.push({ row: e.row, srcPage: e.srcPage }); });
        }
      }
    });
    delete stack[rel];
    memo[rel] = out;
    return out;
  }

  pageCtxs.forEach(function (ctx) {
    const direct = eventsByPage[ctx.rel].filter(function (e) { return e.kind === "script"; }).length;
    const directCss = (ctx.refs ? ctx.refs.css.length : 0);
    const eff = effectiveOf(ctx.rel, {});
    let coreCount = 0, oldCore = false, hasMigrate = false, firstCore = -1, firstMigrate = -1, coreVer = "";
    eff.forEach(function (e, i) {
      model.effectiveRows.push({
        page: ctx.rel, srcPage: e.srcPage, raw: e.row.raw, resolved: e.row.resolved,
        order: i + 1, lib: e.row.meta.lib, ver: e.row.meta.ver,
        isCore: e.row.meta.isCore, isOld: e.row.meta.isOld, isMigrate: e.row.meta.isMigrate
      });
      if (e.row.meta.isCore) { coreCount++; if (firstCore < 0) firstCore = i; if (e.row.meta.isOld) oldCore = true; if (!coreVer) coreVer = e.row.meta.ver; }
      if (e.row.meta.isMigrate) { hasMigrate = true; if (firstMigrate < 0) firstMigrate = i; }
    });
    const effCss = eff.length;
    const migrateAfter = hasMigrate && firstCore >= 0 ? (firstMigrate > firstCore ? "Y" : "N") : "";
    const coreIs35Plus = coreCount > 0 && coreVer && !versionLt(coreVer, TARGET_JQUERY_FLOOR_VERSION);
    model.pages.push({
      rel: ctx.rel, ctx: ctx,
      directScripts: direct, effectiveScripts: eff.length,
      directCss: directCss, effectiveCss: 0,
      hasCore: coreCount > 0, coreCount: coreCount, coreVer: coreVer,
      oldCore: oldCore, hasMigrate: hasMigrate, migrateAfter: migrateAfter,
      riskMultiCore: coreCount > 1, riskOldCore: oldCore,
      riskMigrateMissing: coreIs35Plus && !hasMigrate,
      riskMigrateBeforeCore: migrateAfter === "N" && hasMigrate && coreCount > 0,
      effective: eff
    });
  });
}

function findCtxRel(model, wcRel) {
  const abs = model.fileIndex[wcRel.toLowerCase()];
  if (!abs) return null;
  const rel = toPosix(path.relative(model.webContentRoot, abs));
  return model.ctxByRel[rel] ? rel : null;
}

function analyzeAjax(model) {
  model.textFiles.forEach(function (ctx) {
    if (!ctx.isJs && !ctx.isPage) return;
    if (ctx.isVendor && ctx.lib !== "app") { if (ctx.lib !== "probe") return; }
    ctx.regions.forEach(function (rg) {
      const orig = ctx.text.slice(rg.start, rg.end);
      const code = maskJs(orig, true);
      const push = function (idx, method, urlRaw, dyn, conf, mockType) {
        model.ajaxRows.push({
          rel: ctx.rel, line: lineOf(ctx.lineStarts, rg.start + idx),
          method: method, urlRaw: trunc(urlRaw, 160),
          urlNorm: normalizeAjaxUrl(urlRaw, model), dynamic: dyn ? "Y" : "N",
          confidence: conf, mock: mockType
        });
      };
      let m;
      const ajaxRe = /\$\.(ajax|get|post|getJSON)\s*\(/g;
      while ((m = ajaxRe.exec(code)) !== null) {
        const kind = m[1];
        const open = m.index + m[0].length - 1;
        const close = matchParen(code, open);
        if (close < 0) continue;
        const inner = code.slice(open + 1, close);
        if (kind === "ajax") {
          const um = inner.match(/\burl\s*[:=]\s*(?:"([^"]*)"|'([^']*)')/);
          const tm = inner.match(/\b(?:type|method)\s*[:=]\s*["']([A-Za-z]+)["']/);
          const dj = /dataType\s*[:=]\s*["']json/i.test(inner);
          if (um) push(m.index, tm ? tm[1].toUpperCase() : "GET", um[1] !== undefined ? um[1] : um[2], false, "High", dj ? "json" : "html");
          else {
            const ud = inner.match(/\burl\s*[:=]\s*([^,\r\n}]{1,120})/);
            if (ud) push(m.index, tm ? tm[1].toUpperCase() : "GET", ud[1].trim(), true, "Low", dj ? "json" : "html");
          }
        } else {
          const fm = inner.match(/^\s*(?:"([^"]*)"|'([^']*)')/);
          const method = kind === "post" ? "POST" : "GET";
          if (fm) push(m.index, method, fm[1] !== undefined ? fm[1] : fm[2], false, "High", kind === "getJSON" ? "json" : "html");
          else {
            const dm = inner.match(/^\s*([^,\r\n]{1,120})/);
            if (dm && dm[1].trim()) push(m.index, method, dm[1].trim(), true, "Low", kind === "getJSON" ? "json" : "html");
          }
        }
      }
      const loadRe = /\.load\s*\(\s*(?:"([^"]+)"|'([^']+)')/g;
      while ((m = loadRe.exec(code)) !== null) {
        push(m.index, "GET", m[1] !== undefined ? m[1] : m[2], false, "Medium", "html");
      }
      const xhrRe = /\.open\s*\(\s*["'](GET|POST|PUT|DELETE)["']\s*,\s*(?:"([^"]+)"|'([^']+)')/gi;
      while ((m = xhrRe.exec(code)) !== null) {
        push(m.index, m[1].toUpperCase(), m[2] !== undefined ? m[2] : m[3], false, "High", "json");
      }
    });
  });
}

function normalizeAjaxUrl(u, model) {
  let s = applyPathVars(String(u), model.profile);
  s = s.replace(/\$\{[^}]*\}/g, "_EL_").replace(/<%=?[^%]*%>/g, "_JSP_");
  s = s.split(/[?#]/)[0].trim();
  return s;
}

function analyzeSyntax(model) {
  model.textFiles.forEach(function (ctx) {
    if (!ctx.isJs) return;
    if (ctx.isVendor || ctx.isMin) {
      model.syntaxRows.push({ rel: ctx.rel, result: "SKIPPED", reason: ctx.isMin ? "minified" : "vendor" });
      return;
    }
    if (/<%|<jsp:|<c:/.test(ctx.text.slice(0, 2000))) {
      model.syntaxRows.push({ rel: ctx.rel, result: "SKIPPED", reason: "jsp-fragment" });
      return;
    }
    if (ctx.size > 512 * 1024) {
      model.syntaxRows.push({ rel: ctx.rel, result: "SKIPPED", reason: "too-large" });
      return;
    }
    try {
      new Function(ctx.text);
      model.syntaxRows.push({ rel: ctx.rel, result: "OK", reason: "" });
    } catch (e) {
      model.syntaxRows.push({ rel: ctx.rel, result: "FAIL", reason: trunc(e.message, 160) });
      addFinding(model, ctx, {
        idx: 0, line: 1, category: "js-syntax", pattern: "new Function check",
        priority: "Manual", confidence: "Low", action: "ReviewOnly",
        before: "", reason: "syntax check failed under Node parser (may be legacy-IE-only syntax): " + trunc(e.message, 120),
        commitGroup: "UNKNOWN"
      });
    }
  });
}

const VENDOR_RECOMMEND = {
  "jquery-ui": "jQuery UI <= 1.12.1 has its OWN CVEs (CVE-2021-41182/41183/41184 datepicker XSS, CVE-2022-31160); security scanners flag it even after jQuery core upgrade - move to jQuery UI 1.13.2+ (supports jQuery 3.x), then test datepicker/dialog/button/tabs/autocomplete",
  "jqgrid": "do not hand-edit; classic trirand jqGrid 4.x predates jQuery 3 - plan replacement with free-jqGrid 4.15.x or its maintained fork (jQuery 3.x support) or Guriddo jqGrid 5.5.4+ (commercial, official jQuery 3.5 support); until swapped, test rendering/paging/sort/search/inline edit/formatter/subgrid under Migrate and watch JQMIGRATE warnings from grid files",
  "select2": "select2 4.0.8+ fixed jQuery 3.x compatibility (4.0.5 had focus/multiselect bugs under jQuery 3); 3.5.x line is unmaintained - test placeholder, ajax search, multiple select, initial value binding, or plan upgrade to 4.0.13",
  "autoNumeric": "old autoNumeric 1.x reported working under jQuery 3.x; v4+ is jQuery-free standalone if replacement ever needed; test amount input, comma formatting, blur/focus, saved value, readonly/disabled",
  "datepicker": "test open/close, locale, min/max date under jQuery 3.x",
  "bootstrap": "check bootstrap js version vs jQuery 3.x compatibility",
  "jquery-validate": "test form validation trigger/messages under jQuery 3.x",
  "jquery-core": "core library file; replaced via patch-jquery mode",
  "jquery-migrate": "migrate library; keep during transition, remove after cleanup",
  "vendor-other": "external library; verify jQuery 3.x compatibility or replace"
};

function buildInventories(model) {
  model.allFiles.forEach(function (f) {
    const lib = classifyLib(f.rel, model.profile);
    const isScript = f.ext === ".js";
    const isStyle = f.ext === ".css";
    const isPage = PAGE_EXTS.indexOf(f.ext) >= 0;
    model.dirInv.push([f.rel, isPage ? "page" : isScript ? "script" : isStyle ? "style" : "asset", f.ext, f.size, lib, (lib !== "app" && lib !== "probe") ? "Y" : "N", isPage ? "Y" : "N", isScript ? "Y" : "N", isStyle ? "Y" : "N"]);
    if (isScript) {
      const ctx = model.ctxByRel[f.rel];
      let ver = versionFromName(fileNameOf(f.rel));
      if (lib === "jquery-core" && !ver) ver = sniffJqueryVersion(f.abs);
      const min = ctx ? ctx.isMin : /\.min\.js$/i.test(f.rel);
      let risk = "";
      if (lib === "jquery-core" && ver && versionLt(ver, TARGET_JQUERY_FLOOR_VERSION)) risk = "OLD_JQUERY_CORE_" + CVE_ID;
      else if (lib !== "app") risk = "VENDOR";
      else if (min) risk = "MINIFIED";
      model.scriptInv.push([f.rel, lib, ver, lib !== "app" ? "Y" : "N", min ? "Y" : "N", risk]);
      if (lib !== "app" && lib !== "probe") {
        model.pluginInv.push([f.rel, lib, ver, "path/filename pattern", lib === "jquery-core" && risk ? "High" : "Medium", VENDOR_RECOMMEND[lib] || VENDOR_RECOMMEND["vendor-other"]]);
      }
    }
  });
}

function familyOf(cat) {
  if (cat === "dom-sink" || cat === "dom-factory" || cat === "parse-html") return "dom";
  if (cat.indexOf("bool-attr") === 0) return "boolattr";
  return cat;
}

function dedupFindings(model) {
  const byKey = {};
  const out = [];
  model.findings.forEach(function (f) {
    const key = f.rel + "|" + f.line + "|" + familyOf(f.category);
    const prev = byKey[key];
    if (!prev) { byKey[key] = f; out.push(f); return; }
    const pr = PRIORITY_RANK[prev.priority] || 0;
    const nr = PRIORITY_RANK[f.priority] || 0;
    if (nr > pr && !(prev.action === "Changed" && f.action !== "Changed" && nr <= PRIORITY_RANK.Review)) {
      const i = out.indexOf(prev);
      if (prev.action !== "Changed") { out[i] = f; byKey[key] = f; }
      else out.push(f);
    } else if (f.action === "Changed" && prev.action !== "Changed") {
      out.push(f);
    }
  });
  model.findings = out;
}

function buildQueues(model) {
  const focus = model.findings.filter(function (f) {
    if (f.thirdParty === "Y") return false;
    if (f.priority === "StaticHtmlLow" || f.priority === "Ignored" || f.priority === "VendorReview") return false;
    if (f.category === "aria-attr") return false;
    return f.priority === "Critical" || f.priority === "Manual" || f.priority === "XssHigh" || f.priority === "Review";
  });
  focus.sort(function (a, b) {
    const d = (PRIORITY_RANK[b.priority] || 0) - (PRIORITY_RANK[a.priority] || 0);
    if (d) return d;
    if (a.rel !== b.rel) return a.rel < b.rel ? -1 : 1;
    return a.line - b.line;
  });
  model.focus = focus;

  const byFile = {};
  model.findings.forEach(function (f) {
    if (!byFile[f.rel]) byFile[f.rel] = [];
    byFile[f.rel].push(f);
  });
  Object.keys(byFile).sort().forEach(function (rel) {
    const fs2 = byFile[rel];
    const cnt = {};
    fs2.forEach(function (f) { cnt[f.priority] = (cnt[f.priority] || 0) + 1; });
    const blockers = (cnt.Critical || 0) + (cnt.Manual || 0) + (cnt.Review || 0) + (cnt.XssHigh || 0) + (cnt.VendorReview || 0);
    const result = blockers === 0 ? "AutoFixOnlyCompleteCandidate" : "NeedsReviewOrManual";
    model.completeRows.push([
      rel, result, fs2.length,
      cnt.AutoFixed || 0, cnt.AutoFixed2 || 0, cnt.StaticHtmlLow || 0,
      cnt.Critical || 0, cnt.Manual || 0, cnt.Review || 0, cnt.XssHigh || 0, cnt.VendorReview || 0,
      result === "AutoFixOnlyCompleteCandidate" ? "only auto-fixed/low findings; no further change expected from pattern scan" : "remaining items need human review"
    ]);
    if (blockers > 0) {
      const cats = uniq(fs2.filter(function (f) { return PRIORITY_RANK[f.priority] >= PRIORITY_RANK.Review || f.priority === "VendorReview"; }).map(function (f) { return f.category; })).slice(0, 6).join(" ");
      model.needsRows.push([rel, cnt.Critical || 0, cnt.XssHigh || 0, cnt.Manual || 0, cnt.Review || 0, cnt.VendorReview || 0, cats]);
    }
  });
}

function isAmbiguousFinding(f) {
  if (f.thirdParty === "Y") return false;
  if (f.priority === "Review") return true;
  if (f.priority === "Manual") return true;
  if (f.priority === "XssHigh" && f.confidence !== "High") return true;
  if (f.category === "jquery-core-unknown") return true;
  return false;
}

function countCallSites(model, name) {
  const re = new RegExp("(^|[^A-Za-z0-9_$.])" + escapeRe(name) + "\\s*\\(", "g");
  let n = 0;
  model.textFiles.forEach(function (c2) {
    c2.regions.forEach(function (rg) {
      re.lastIndex = 0;
      while (re.exec(rg.masked) !== null) n++;
    });
  });
  return n;
}

const REVIEW_QUESTIONS = Object.assign(Object.create(null), {
  "jqxhr-shorthand": "이 콜백은 AJAX 성공/에러 콜백인가요? 콜백의 첫 인자는 항상 서버에서 온 JSON/데이터인가요? (A: AJAX 성공, B: AJAX 에러, C: DOM 이벤트, D: 모름)",
  "dom-sink": "이 인자 값은 어디서 오나요? (A: 서버 응답/AJAX 콜백, B: 사용자 입력, C: 내부에서 안전하게 생성된 값, D: 알 수 없음) HTML 태그가 실제로 섞여 들어갈 수 있나요? (Y/N/모름)",
  "wrapper-dom-sink": "이 래퍼 함수가 내부적으로 jQuery .html()/.append()를 쓰나요? 인자로 들어오는 값이 서버 데이터인가요? (Y/N/모름)",
  "dom-factory": "이 문자열이 항상 고정 literal인가요, 아니면 조합되나요? (A: 고정, B: 조합, C: 모름)",
  "parse-html": "parseHTML에 들어가는 문자열이 서버 응답을 포함하나요? (Y/N/모름)",
  "bool-attr-variable": "이 변수가 실제로 가질 수 있는 값은 무엇인가요? (예: Y/N, true/false, 1/0, 기타 - 적어주세요)",
  "trim-deprecated": "$.trim 인자가 항상 문자열인가요, 아니면 null/undefined가 올 수 있나요? (A: 항상 문자열, B: null 가능, C: 모름)",
  "jquery-core-unknown": "이 jQuery 파일의 실제 버전을 알고 있나요? (버전 문자열 또는 '모름')",
  "live-die": "이 selector가 동적으로 추가되는 요소를 대상으로 하나요? (Y/N/모름)",
  "js-syntax": "이 파일이 실제로 구형 IE 전용 문법(conditional comments 등)을 쓰나요, 아니면 다른 이유로 파싱이 실패했나요?"
});
function questionFor(category) {
  return REVIEW_QUESTIONS[category] || "이 코드의 역할은 무엇인가요? (자유 설명)";
}

const REVIEW_QUESTIONS_SHORT = Object.assign(Object.create(null), {
  "jqxhr-shorthand": "ajax cb? arg0 server data? A:success B:error C:event D:?",
  "dom-sink": "sink arg origin? A:server B:user C:safe D:? html possible?",
  "wrapper-dom-sink": "wrapper uses html/append? arg server data? Y/N/?",
  "dom-factory": "html string fixed or built? A:fixed B:built C:?",
  "parse-html": "parseHTML input includes server data? Y/N/?",
  "bool-attr-variable": "possible values? Y/N true/false 1/0 other?",
  "trim-deprecated": "$.trim arg always string? A:string B:nullable C:?",
  "jquery-core-unknown": "jquery version? value or ?",
  "live-die": "selector targets dynamic elements? Y/N/?",
  "js-syntax": "legacy IE syntax or real parse issue?"
});
function shortQuestionFor(category) {
  return REVIEW_QUESTIONS_SHORT[category] || "role/intent?";
}

function shortReviewPath(rel) {
  let s = toPosix(rel || "");
  s = s.replace(/^WebContent\//i, "");
  s = s.replace(/^WEB-INF\/views\//i, "v/");
  s = s.replace(/^WEB-INF\/layouts\//i, "l/");
  s = s.replace(/^resources\//i, "r/");
  const parts = s.split("/").filter(Boolean);
  if (parts.length > 4) s = ".../" + parts.slice(-4).join("/");
  return s;
}

function compactLocations(locs, max) {
  const out = [];
  const seen = Object.create(null);
  locs.forEach(function (loc) {
    const m = /^(.+):(\d+)$/.exec(loc);
    const shortLoc = m ? (shortReviewPath(m[1]) + ":" + m[2]) : shortReviewPath(loc);
    if (!seen[shortLoc]) { seen[shortLoc] = 1; out.push(shortLoc); }
  });
  if (out.length <= max) return out.join(" ");
  return out.slice(0, max).join(" ") + " +" + (out.length - max);
}

function compactExcerptText(excerpt) {
  const out = [];
  const seen = Object.create(null);
  String(excerpt || "").split(/\n/).forEach(function (line) {
    let s = line.replace(/\r$/, "").replace(/^\s{0,3}(\d+:)/, "$1").replace(/^>>\s*/, ">");
    s = s.replace(/[ \t]+/g, " ").trimEnd();
    const key = s.replace(/^>\s*/, "").replace(/^\d+:\s*/, "");
    if (key && seen[key]) return;
    if (key) seen[key] = 1;
    out.push(s);
  });
  return out.join("\n");
}

function bucketOf(len) {
  if (len > 30) return "long";
  if (len > 8) return "med";
  return "short";
}

function redactSourceText(text) {
  const n = text.length;
  const out = [];
  let i = 0;
  let lastSig = "";
  let lastWord = "";
  let prevWasWord = false;
  const REGEX_WORDS = Object.assign(Object.create(null), { "return": 1, "typeof": 1, "instanceof": 1, "in": 1, "of": 1, "new": 1, "delete": 1, "void": 1, "case": 1, "do": 1, "else": 1, "throw": 1 });
  while (i < n) {
    const c = text[i];
    const d = i + 1 < n ? text[i + 1] : "";
    if (c === "<" && text.slice(i, i + 4) === "<%--") {
      let j = i + 4;
      let nl = 0;
      while (j < n && text.slice(j, j + 3) !== "--%>") { if (text[j] === "\n") nl++; j++; }
      if (j < n) j += 3;
      out.push("<%--<COMMENT>--%>" + "\n".repeat(nl));
      i = j;
      continue;
    }
    if (c === "/" && d === "/") {
      while (i < n && text[i] !== "\n") i++;
      out.push("//<COMMENT>");
      continue;
    }
    if (c === "/" && d === "*") {
      let j = i + 2;
      let nl = 0;
      while (j < n && !(text[j] === "*" && text[j + 1] === "/")) { if (text[j] === "\n") nl++; j++; }
      if (j < n) j += 2;
      out.push("/*<COMMENT>*/" + "\n".repeat(nl));
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      const q = c;
      i++;
      let len = 0;
      while (i < n) {
        if (text[i] === "\\" && i + 1 < n) { len += 2; i += 2; continue; }
        if (text[i] === q) { i++; break; }
        if (text[i] === "\n") break;
        len++; i++;
      }
      out.push(q + "<STR:" + bucketOf(len) + ">" + q);
      lastSig = q; prevWasWord = false;
      continue;
    }
    if (c === "`") {
      i++;
      let len = 0;
      let nl = 0;
      while (i < n) {
        if (text[i] === "\\" && i + 1 < n) { len += 2; i += 2; continue; }
        if (text[i] === "`") { i++; break; }
        if (text[i] === "\n") nl++;
        len++; i++;
      }
      out.push("`<STR:" + bucketOf(len) + ">`" + "\n".repeat(nl));
      lastSig = "`"; prevWasWord = false;
      continue;
    }
    if (c === "/") {
      let regexOk = false;
      if (lastSig === "") regexOk = true;
      else if ("(,=:[!&|?{};+-*%~^<>".indexOf(lastSig) >= 0) regexOk = true;
      else if (/[A-Za-z0-9_$]/.test(lastSig) && REGEX_WORDS[lastWord]) regexOk = true;
      if (regexOk) {
        i++;
        let inClass = false;
        let bailed = false;
        while (i < n) {
          if (text[i] === "\\" && i + 1 < n) { i += 2; continue; }
          if (text[i] === "[") { inClass = true; i++; continue; }
          if (text[i] === "]") { inClass = false; i++; continue; }
          if (text[i] === "/" && !inClass) { i++; break; }
          if (text[i] === "\n") { bailed = true; break; }
          i++;
        }
        if (!bailed) {
          while (i < n && /[a-z]/i.test(text[i])) i++;
          out.push("/<REGEX>/");
          lastSig = "/"; prevWasWord = false;
          continue;
        }
      }
    }
    out.push(c);
    if (/\s/.test(c)) {
      prevWasWord = false;
    } else {
      lastSig = c;
      if (/[A-Za-z0-9_$]/.test(c)) { lastWord = prevWasWord ? lastWord + c : c; prevWasWord = true; }
      else { lastWord = ""; prevWasWord = false; }
    }
    i++;
  }
  return out.join("");
}

function applySensitiveIdentifiers(model, line) {
  let out = line;
  (model.profile.sensitiveIdentifiers || []).forEach(function (nm, i) {
    if (!nm) return;
    out = out.replace(new RegExp("(?<![A-Za-z0-9])" + escapeRe(nm) + "(?![A-Za-z0-9])", "gi"), "VAR" + (i + 1));
  });
  return out;
}

function excerptFor(model, ctx, idx, contextLines) {
  const line = lineOf(ctx.lineStarts, idx || 0);
  if (!ctx._redactedLines) {
    ctx._redactedLines = redactSourceText(ctx.text).split("\n");
  }
  const totalLines = ctx._redactedLines.length;
  const lo = Math.max(1, line - contextLines);
  const hi = Math.min(totalLines, line + contextLines);
  const out = [];
  for (let ln = lo; ln <= hi; ln++) {
    const raw = (ctx._redactedLines[ln - 1] || "").replace(/\r$/, "");
    out.push((ln === line ? ">> " : "   ") + ln + ": " + applySensitiveIdentifiers(model, raw));
  }
  return out.join("\n");
}

function buildReviewCases(model) {
  const ambiguous = model.findings.filter(isAmbiguousFinding);
  const groups = Object.create(null);
  ambiguous.forEach(function (f) {
    const key = f._caseId;
    if (!groups[key]) {
      groups[key] = { caseId: key, kind: f._groupKind, name: f._groupName, findings: [], categories: Object.create(null) };
    }
    groups[key].findings.push(f);
    groups[key].categories[f.category] = (groups[key].categories[f.category] || 0) + 1;
  });
  let list = Object.keys(groups).map(function (k) { return groups[k]; });
  const weight = Object.assign(Object.create(null), { Manual: 3, XssHigh: 3, Review: 2, Critical: 4 });
  list.forEach(function (g) {
    g.weightBase = g.findings.reduce(function (s, f) { return s + (weight[f.priority] || 1); }, 0);
  });
  list.sort(function (a, b) { return b.weightBase - a.weightBase; });
  const maxCases = positiveIntOpt(model.opts["max-review-cases"], 20);
  const preTop = list.slice(0, Math.max(maxCases * 3, maxCases));
  preTop.forEach(function (g) {
    g.fanout = g.kind === "FN" ? countCallSites(model, g.name) : 0;
    g.score = g.weightBase * (1 + Math.log2(1 + g.fanout));
  });
  preTop.sort(function (a, b) { return b.score - a.score; });
  const top = preTop.slice(0, maxCases);
  const contextLines = positiveIntOpt(model.opts["context-lines"], 1);
  top.forEach(function (g) {
    const rep = g.findings[0];
    const ctx = model.ctxByRel[rep.rel];
    g.repFile = rep.rel;
    g.repLine = rep.line;
    g.excerpt = ctx ? excerptFor(model, ctx, rep.idx || 0, contextLines) : "(no excerpt available)";
    g.topCategories = Object.keys(g.categories).sort(function (a, b) { return g.categories[b] - g.categories[a]; }).slice(0, 2);
    g.question = questionFor(g.topCategories[0]);
    g.shortQuestion = shortQuestionFor(g.topCategories[0]);
    g.sampleLocations = uniq(g.findings.map(function (f) { return f.rel + ":" + f.line; })).slice(0, 3);
    g.sampleLocationsShort = compactLocations(uniq(g.findings.map(function (f) { return f.rel + ":" + f.line; })), 3);
    g.compactExcerpt = compactExcerptText(g.excerpt);
    g.count = g.findings.length;
  });
  model.reviewCases = top;
  model.reviewCasesAll = list.length;
}

function summarize(model) {
  const c = {};
  const P = ["Critical", "AutoFixed", "AutoFixed2", "Review", "Manual", "XssHigh", "VendorReview", "StaticHtmlLow", "Ignored"];
  P.forEach(function (p) { c[p] = 0; });
  model.findings.forEach(function (f) { if (c[f.priority] !== undefined) c[f.priority]++; });
  const libCounts = {};
  model.scriptInv.forEach(function (r) { libCounts[r[1]] = (libCounts[r[1]] || 0) + 1; });
  const changedCandidates = {};
  model.findings.forEach(function (f) { if (f.action === "Changed") changedCandidates[f.rel] = 1; });
  model.counters = {
    SourceRoot: model.sourceRoot,
    WebContentRoot: model.webContentRoot,
    TargetRoot: model.targetRoot || "(not set)",
    ReportRoot: model.reportRoot || "(not set)",
    Mode: model.mode,
    JqueryTargetVersion: model.profile.jquery.targetVersion,
    JqueryFloorVersion: TARGET_JQUERY_FLOOR_VERSION,
    Gate35Blockers: c.Critical,
    TotalFiles: model.allFiles.length,
    TextFiles: model.textFiles.length,
    PageFiles: model.textFiles.filter(function (x) { return x.isPage; }).length,
    JsFiles: model.textFiles.filter(function (x) { return x.isJs; }).length,
    ChangedFiles: Object.keys(model.changed).length || Object.keys(changedCandidates).length,
    ApiFindings: model.findings.length,
    Critical: c.Critical,
    AutoFixed: c.AutoFixed,
    AutoFixed2: c.AutoFixed2,
    Review: c.Review,
    Manual: c.Manual,
    XssHigh: c.XssHigh,
    FocusQueue: model.focus.length,
    VendorReview: c.VendorReview,
    StaticHtmlLow: c.StaticHtmlLow,
    Ignored: c.Ignored,
    JqueryLoads: model.jqueryLoadRows.length,
    OldJqueryBelow350: model.oldCoreRefs.length,
    PageRiskMultipleJqueryCore: model.pages.filter(function (p) { return p.riskMultiCore; }).length,
    PageRiskOldJqueryCore: model.pages.filter(function (p) { return p.riskOldCore; }).length,
    PageRiskMigrateMissing: model.pages.filter(function (p) { return p.riskMigrateMissing; }).length,
    PageRiskMigrateBeforeCore: model.pages.filter(function (p) { return p.riskMigrateBeforeCore; }).length,
    UnresolvedRefs: model.unresolvedRows.length,
    AjaxEndpoints: model.ajaxRows.length,
    JsSyntaxFail: model.syntaxRows.filter(function (r) { return r.result === "FAIL"; }).length,
    LibraryCounts: JSON.stringify(libCounts),
    GitInfo: model.git && model.git.available ? (model.git.branch + " changed=" + model.git.changed.length + " untracked=" + model.git.untracked.length) : "Unavailable",
    OldJquerySrcs: model.oldCoreRefs.map(function (r) { return r.page + ":" + r.line + ":" + r.raw; }).join(" | "),
    ReviewCasesTotal: model.reviewCasesAll,
    ReviewCasesInPack: model.reviewCases.length,
    LearnedWrapperCount: model.wrapperNames.length,
    LearnedFindingOverrides: Object.keys(model.learnedFindingsMap || {}).length
  };
}

function applyEditsToText(ctx) {
  const edits = [];
  ctx.findings.forEach(function (f) {
    if (f.action === "Changed" && f.editStart !== undefined && f.editEnd !== undefined && f.replacement !== undefined) {
      edits.push({ s: f.editStart, e: f.editEnd, r: f.replacement, f: f });
    }
  });
  if (edits.length === 0) return null;
  edits.sort(function (a, b) { return a.s - b.s; });
  const applied = [];
  let lastEnd = -1;
  edits.forEach(function (ed) {
    if (ed.s < lastEnd) { ed.f.reason = trunc(ed.f.reason + " [skipped: overlapping edit]", 300); ed.f.action = "ReviewOnly"; return; }
    applied.push(ed);
    lastEnd = ed.e;
  });
  let text = ctx.text;
  for (let i = applied.length - 1; i >= 0; i--) {
    const ed = applied[i];
    text = text.slice(0, ed.s) + ed.r + text.slice(ed.e);
  }
  return { text: text, count: applied.length };
}

function writeTarget(model, flags) {
  if (!model.targetRoot) throw new Error("--target is required for mode " + model.mode);
  log("writing TO-BE tree: " + model.targetRoot);
  ensureDir(model.targetRoot);
  const excl = [model.targetRoot];
  if (model.reportRoot) excl.push(model.reportRoot);
  const all = walkFiles(model.sourceRoot, excl);
  const patchedByProj = {};
  model.textFiles.forEach(function (ctx) {
    const res = applyEditsToText(ctx);
    if (res) patchedByProj[ctx.projRel] = { ctx: ctx, text: res.text, count: res.count };
  });
  let copied = 0;
  all.forEach(function (f) {
    const projRel = toPosix(path.relative(model.sourceRoot, f.abs));
    const dest = path.join(model.targetRoot, projRel.split("/").join(path.sep));
    ensureDir(path.dirname(dest));
    const patched = patchedByProj[projRel];
    if (patched) {
      writeLatin1(dest, patched.text);
      model.changed[patched.ctx.rel] = { projRel: projRel, edits: patched.count, kind: "autofix" };
    } else {
      fs.copyFileSync(f.abs, dest);
    }
    copied++;
  });
  log("copied " + copied + " files, auto-fixed " + Object.keys(patchedByProj).length + " files");
  if (flags.patch) patchJqueryCore(model);
  if (flags.probe) injectProbe(model);
  model.counters.ChangedFiles = Object.keys(model.changed).length;
}

function targetPathOf(model, ctx) {
  return path.join(model.targetRoot, ctx.projRel.split("/").join(path.sep));
}

function findScriptSrcSpan(text, refRow) {
  if (refRow.srcStart !== undefined && refRow.srcEnd !== undefined && text.slice(refRow.srcStart, refRow.srcEnd) === refRow.raw) {
    return { start: refRow.srcStart, end: refRow.srcEnd, tagStart: refRow.tagStart !== undefined ? refRow.tagStart : refRow.idx };
  }
  const scriptOpenRe = /<script\b[^>]*>/gi;
  let m;
  let best = null;
  const wantedIdx = refRow.tagStart !== undefined ? refRow.tagStart : 0;
  while ((m = scriptOpenRe.exec(text)) !== null) {
    const info = scriptSrcInfo(m[0], m.index);
    if (!info || info.raw !== refRow.raw) continue;
    const distance = Math.abs(m.index - wantedIdx);
    if (!best || distance < best.distance) {
      best = { start: info.srcStart, end: info.srcEnd, tagStart: m.index, distance: distance };
    }
  }
  return best;
}

function findScriptTagStartForSrc(text, src) {
  const scriptOpenRe = /<script\b[^>]*>/gi;
  let m;
  while ((m = scriptOpenRe.exec(text)) !== null) {
    const info = scriptSrcInfo(m[0], m.index);
    if (info && info.raw === src) return m.index;
  }
  return -1;
}

function migrateTraceSnippet(indent, eol) {
  return indent + "<script>" + eol +
    indent + "jQuery.migrateTrace = true; jQuery.migrateMute = false;" + eol +
    indent + "</script>";
}

function ensureMigrateTraceAfterMigrate(text, ctx) {
  if (!ctx.model.profile.jquery.migrateTrace) return { text: text, changed: false, reason: "disabled" };
  if (/jQuery\s*\.\s*migrateTrace\b/.test(text) || /jQuery\s*\.\s*migrateMute\b/.test(text)) {
    return { text: text, changed: false, reason: "already present" };
  }
  const re = /<script\b[^>]*\bsrc\s*=\s*(["'])[^"']*jquery[-.]migrate[^"']*\1[^>]*>\s*<\/script>/ig;
  const m = re.exec(text);
  if (!m) return { text: text, changed: false, reason: "migrate script tag not found" };
  const lineStart = text.lastIndexOf("\n", m.index) + 1;
  const indent = (text.slice(lineStart, m.index).match(/^[ \t]*/) || [""])[0];
  const eol = ctx.eol || "\n";
  const insertAt = m.index + m[0].length;
  return {
    text: text.slice(0, insertAt) + eol + migrateTraceSnippet(indent, eol) + text.slice(insertAt),
    changed: true,
    reason: "inserted after Migrate"
  };
}

function patchJqueryCore(model) {
  const jq = model.profile.jquery;
  if (model.oldCoreRefs.length === 0) {
    log("patch-jquery: no old jQuery core references found");
    return;
  }
  const byCtx = {};
  model.oldCoreRefs.forEach(function (r) {
    if (!byCtx[r.ctx.rel]) byCtx[r.ctx.rel] = [];
    byCtx[r.ctx.rel].push(r);
  });
  Object.keys(byCtx).forEach(function (rel) {
    const ctx = model.ctxByRel[rel];
    const tPath = targetPathOf(model, ctx);
    if (!exists(tPath)) { model.patchResults.push([rel, "", "SKIP", "target file missing"]); return; }
    let text = readLatin1(tPath);
    let changed = false;
    let firstNewSrc = "";
    byCtx[rel].forEach(function (r) {
      if (/^(https?:)?\/\//i.test(r.raw)) {
        model.patchResults.push([rel, r.raw, "MANUAL", "external/CDN url not auto-replaced"]);
        return;
      }
      const slash = r.raw.lastIndexOf("/");
      const prefix = slash >= 0 ? r.raw.slice(0, slash + 1) : "";
      const newSrc = jq.newJquerySrc || (prefix + jq.coreFile);
      const migSrc = jq.newMigrateSrc || (prefix + jq.migrateFile);
      if (!jq.newJquerySrc) {
        const chk = resolveRef(newSrc, rel, model);
        const tAbs = chk.resolved ? path.join(model.targetWcRoot, chk.resolved.split("/").join(path.sep)) : "";
        if (!tAbs || !exists(tAbs)) {
          model.patchResults.push([rel, r.raw, "SKIP", "new core file not found in target: " + (chk.resolved || newSrc) + " (put " + jq.coreFile + " under WebContent/js first)"]);
          return;
        }
        const chk2 = resolveRef(migSrc, rel, model);
        const tAbs2 = chk2.resolved ? path.join(model.targetWcRoot, chk2.resolved.split("/").join(path.sep)) : "";
        if (!tAbs2 || !exists(tAbs2)) {
          model.patchResults.push([rel, r.raw, "SKIP", "migrate file not found in target: " + (chk2.resolved || migSrc)]);
          return;
        }
      }
      const span = findScriptSrcSpan(text, r);
      if (!span) {
        model.patchResults.push([rel, r.raw, "SKIP", "script src span not found in target text (already changed?)"]);
        return;
      }
      text = text.slice(0, span.start) + newSrc + text.slice(span.end);
      changed = true;
      if (!firstNewSrc) firstNewSrc = newSrc;
      model.patchResults.push([rel, r.raw, "REPLACED", newSrc]);
      addFinding(model, ctx, {
        idx: 0, line: r.line, category: "jquery-core-patched", pattern: "patch-jquery",
        priority: "AutoFixed", confidence: "High", action: "Changed",
        before: r.raw, after: newSrc + " (+ migrate)",
        reason: "old jQuery core replaced in TO-BE by patch-jquery mode",
        commitGroup: "JQUERY_CORE"
      });
    });
    if (changed) {
      if (!/jquery[-.]migrate/i.test(text) && firstNewSrc) {
        const lines = text.split("\n");
        const tagStart = findScriptTagStartForSrc(text, firstNewSrc);
        if (tagStart >= 0) {
          const lineIdx = text.slice(0, tagStart).split("\n").length - 1;
          const indent = (lines[lineIdx].match(/^[ \t]*/) || [""])[0];
          const slash2 = firstNewSrc.lastIndexOf("/");
          const migSrc2 = jq.newMigrateSrc || (firstNewSrc.slice(0, slash2 + 1) + jq.migrateFile);
          const eol = ctx.eol === "\r\n" && lines[lineIdx].slice(-1) === "\r" ? "\r" : "";
          lines.splice(lineIdx + 1, 0, indent + '<script type="text/javascript" src="' + migSrc2 + '"></script>' + eol);
        }
        text = lines.join("\n");
      }
      const trace = ensureMigrateTraceAfterMigrate(text, ctx);
      if (trace.changed) {
        text = trace.text;
        model.patchResults.push([rel, "jQuery.migrateTrace", "TRACING", trace.reason]);
      } else if (jq.migrateTrace && trace.reason !== "already present") {
        model.patchResults.push([rel, "jQuery.migrateTrace", "SKIP", trace.reason]);
      }
      writeLatin1(tPath, text);
      model.changed[rel] = { projRel: ctx.projRel, edits: (model.changed[rel] ? model.changed[rel].edits : 0) + 1, kind: "patch-jquery" };
    }
  });
  const replaced = model.patchResults.filter(function (r) { return r[2] === "REPLACED"; }).length;
  const skipped = model.patchResults.filter(function (r) { return r[2] === "SKIP"; }).length;
  log("patch-jquery: replaced=" + replaced + " skipped=" + skipped + " manual=" + model.patchResults.filter(function (r) { return r[2] === "MANUAL"; }).length);
  if (skipped > 0) warn("some references were skipped; see patch_jquery_result.txt in report");
}

function chooseProbeTargets(model) {
  const hints = (model.profile.probe.injectTargetHints || []).map(function (h) { return toPosix(h).toLowerCase(); });
  let targets = model.pages.filter(function (p) {
    const rl = p.rel.toLowerCase();
    return hints.some(function (h) { return rl === h || rl.slice(-h.length) === h; });
  });
  if (targets.length === 0) {
    targets = model.pages.filter(function (p) {
      return p.rel.toLowerCase().indexOf("web-inf/layouts/") === 0 && p.ctx.refs && p.ctx.refs.scripts.some(function (s) { return isJqueryCoreName(fileNameOf(s.raw)); });
    });
  }
  if (targets.length === 0) {
    targets = model.pages.filter(function (p) {
      return p.ctx.refs && p.ctx.refs.scripts.some(function (s) { return isJqueryCoreName(fileNameOf(s.raw)); });
    }).slice(0, 5);
  }
  return targets;
}

function injectProbe(model) {
  const probeAbs = path.join(model.targetWcRoot, "js", PROBE_FILE_NAME);
  writeLatin1(probeAbs, genProbeJs());
  log("probe written: " + probeAbs);
  const targets = chooseProbeTargets(model);
  if (targets.length === 0) {
    warn("probe: no injection target page found; add probe.injectTargetHints to project-profile.json");
    return;
  }
  targets.forEach(function (p) {
    const ctx = p.ctx;
    const tPath = targetPathOf(model, ctx);
    if (!exists(tPath)) { model.probeInjections.push([p.rel, "SKIP", "target file missing"]); return; }
    let text = readLatin1(tPath);
    if (text.indexOf(PROBE_FILE_NAME) >= 0) { model.probeInjections.push([p.rel, "SKIP", "already injected"]); return; }
    let prefix = "";
    if (ctx.refs) {
      const core = ctx.refs.scripts.filter(function (s) { return isJqueryCoreName(fileNameOf(s.raw)) && !/^(https?:)?\/\//i.test(s.raw); })[0];
      const anyJs = core || ctx.refs.scripts.filter(function (s) { return !/^(https?:)?\/\//i.test(s.raw); })[0];
      if (anyJs) {
        const slash = anyJs.raw.lastIndexOf("/");
        prefix = slash >= 0 ? anyJs.raw.slice(0, slash + 1) : "";
      }
    }
    if (!prefix) prefix = "${pageContext.request.contextPath}/js/";
    const tag = '<script type="text/javascript" src="' + prefix + PROBE_FILE_NAME + '"></script>';
    const bodyClose = text.search(/<\/body\s*>/i);
    if (bodyClose >= 0) text = text.slice(0, bodyClose) + tag + ctx.eol + text.slice(bodyClose);
    else text = text + ctx.eol + tag + ctx.eol;
    writeLatin1(tPath, text);
    model.changed[p.rel] = { projRel: ctx.projRel, edits: (model.changed[p.rel] ? model.changed[p.rel].edits : 0) + 1, kind: "probe" };
    model.probeInjections.push([p.rel, "INJECTED", prefix + PROBE_FILE_NAME]);
    addFinding(model, ctx, {
      idx: 0, line: 0, category: "probe-injected", pattern: PROBE_FILE_NAME,
      priority: "Ignored", confidence: "High", action: "Changed",
      before: "", after: tag,
      reason: "runtime probe injected for verification; must be removed before production (verify-clean checks this)",
      commitGroup: "PROBE_ONLY"
    });
  });
  log("probe injected into " + model.probeInjections.filter(function (r) { return r[1] === "INJECTED"; }).length + " page(s)");
}

function genProbeJs() {
  const L = [];
  L.push("(function(){");
  L.push("if (window.__JQ35_PROBE__) { return; }");
  L.push("window.__JQ35_PROBE__ = true;");
  L.push("var MARKER = '" + PROBE_MARKER + "';");
  L.push("var logs = [];");
  L.push("var t0 = new Date().getTime();");
  L.push("function stamp(){ return String(new Date().getTime() - t0); }");
  L.push("function push(level, msg){ try { logs.push('[' + stamp() + 'ms][' + level + '] ' + msg); if (logs.length > 800) { logs.shift(); } refreshSoon(); } catch(e){} }");
  L.push("function fmt(args){ var out = []; var i; for (i = 0; i < args.length; i++) { var a = args[i]; if (a === null) { out.push('null'); } else if (typeof a === 'undefined') { out.push('undefined'); } else if (typeof a === 'object') { try { out.push(JSON.stringify(a)); } catch(e) { out.push(String(a)); } } else { out.push(String(a)); } } return out.join(' '); }");
  L.push("var origWarn = window.console && console.warn ? console.warn : null;");
  L.push("var origError = window.console && console.error ? console.error : null;");
  L.push("var origLog = window.console && console.log ? console.log : null;");
  L.push("if (!window.console) { window.console = {}; }");
  L.push("console.warn = function(){ var m = fmt(arguments); push(m.indexOf('JQMIGRATE') === 0 ? 'JQMIGRATE' : 'WARN', m); if (origWarn) { try { origWarn.apply(console, arguments); } catch(e){} } };");
  L.push("console.error = function(){ push('ERROR', fmt(arguments)); if (origError) { try { origError.apply(console, arguments); } catch(e){} } };");
  L.push("console.log = function(){ var m = fmt(arguments); if (m.indexOf('JQMIGRATE') === 0) { push('JQMIGRATE', m); } if (origLog) { try { origLog.apply(console, arguments); } catch(e){} } };");
  L.push("var prevOnError = window.onerror;");
  L.push("window.onerror = function(msg, src, line, col, err){ push('JSERROR', msg + ' @ ' + src + ':' + line + (col ? ':' + col : '')); if (prevOnError) { try { return prevOnError.apply(window, arguments); } catch(e){} } return false; };");
  L.push("function jqInfo(){ var o = { jquery: '(none)', migrate: '(none)', ui: '(none)', jqgrid: 'N', select2: 'N', autoNumeric: 'N' }; try { var jq = window.jQuery; if (jq) { o.jquery = jq.fn && jq.fn.jquery ? jq.fn.jquery : 'unknown'; if (jq.migrateVersion) { o.migrate = jq.migrateVersion; } if (jq.ui && jq.ui.version) { o.ui = jq.ui.version; } if (jq.fn && jq.fn.jqGrid) { o.jqgrid = 'Y'; } if (jq.jgrid) { o.jqgrid = 'Y'; } if (jq.fn && jq.fn.select2) { o.select2 = 'Y'; } if (jq.fn && jq.fn.autoNumeric) { o.autoNumeric = 'Y'; } } if (window.AutoNumeric) { o.autoNumeric = 'Y'; } } catch(e){} return o; }");
  L.push("function scriptList(){ var out = []; try { var ss = document.getElementsByTagName('script'); var i; for (i = 0; i < ss.length; i++) { if (ss[i].src) { out.push(ss[i].src); } } } catch(e){} return out; }");
  L.push("function buildText(){ var o = jqInfo(); var lines = []; lines.push(MARKER); lines.push('URL=' + window.location.href); lines.push('time=' + new Date().toString()); lines.push('jQuery=' + o.jquery); lines.push('Migrate=' + o.migrate); lines.push('jQueryUI=' + o.ui); lines.push('jqGrid detected=' + o.jqgrid); lines.push('select2 detected=' + o.select2); lines.push('autoNumeric detected=' + o.autoNumeric); lines.push(''); lines.push('[logs ' + logs.length + ']'); var i; for (i = 0; i < logs.length; i++) { lines.push(logs[i]); } lines.push(''); lines.push('[scripts]'); var sc = scriptList(); for (i = 0; i < sc.length; i++) { lines.push(sc[i]); } return lines.join('\\r\\n'); }");
  L.push("var panel = null; var ta = null; var badge = null; var timer = null;");
  L.push("function refreshSoon(){ if (timer) { return; } timer = window.setTimeout(function(){ timer = null; refresh(); }, 400); }");
  L.push("function refresh(){ if (ta) { ta.value = buildText(); } if (badge) { var errs = 0; var migs = 0; var i; for (i = 0; i < logs.length; i++) { if (logs[i].indexOf('[JSERROR]') >= 0 || logs[i].indexOf('[ERROR]') >= 0 || logs[i].indexOf('[AJAXERROR]') >= 0) { errs++; } if (logs[i].indexOf('[JQMIGRATE]') >= 0) { migs++; } } badge.innerHTML = 'JQ35 E:' + errs + ' M:' + migs; badge.style.background = errs > 0 ? '#b00020' : (migs > 0 ? '#b26a00' : '#1b5e20'); } }");
  L.push("function sendLog(){ try { var xhr = new XMLHttpRequest(); xhr.open('POST', '/__probe/log', true); xhr.setRequestHeader('Content-Type', 'text/plain'); xhr.onreadystatechange = function(){ if (xhr.readyState === 4) { push('PROBE', 'send status=' + xhr.status); } }; xhr.send(buildText()); } catch(e) { push('PROBE', 'send failed: ' + e.message); } }");
  L.push("function copyLog(){ try { ta.focus(); ta.select(); var ok = document.execCommand('copy'); push('PROBE', 'copy=' + ok); } catch(e) { push('PROBE', 'copy failed, select manually'); } }");
  L.push("function buildPanel(){ if (panel) { return; } if (!document.body) { return; }");
  L.push("badge = document.createElement('div');");
  L.push("badge.style.cssText = 'position:fixed;right:8px;bottom:8px;z-index:999999;background:#1b5e20;color:#fff;font:12px/1.6 monospace;padding:3px 10px;cursor:pointer;border-radius:3px;';");
  L.push("badge.innerHTML = 'JQ35';");
  L.push("panel = document.createElement('div');");
  L.push("panel.style.cssText = 'position:fixed;right:8px;bottom:36px;z-index:999999;width:560px;max-width:95%;background:#111;color:#eee;border:1px solid #555;display:none;font:12px monospace;padding:6px;';");
  L.push("var bar = document.createElement('div');");
  L.push("function mkBtn(txt, fn){ var b = document.createElement('button'); b.innerHTML = txt; b.style.cssText = 'margin:0 4px 4px 0;font:12px monospace;padding:2px 8px;'; if (b.attachEvent) { b.attachEvent('onclick', fn); } else { b.addEventListener('click', fn, false); } return b; }");
  L.push("bar.appendChild(mkBtn('Refresh', refresh));");
  L.push("bar.appendChild(mkBtn('Copy', copyLog));");
  L.push("bar.appendChild(mkBtn('Send', sendLog));");
  L.push("bar.appendChild(mkBtn('Clear', function(){ logs = []; refresh(); }));");
  L.push("panel.appendChild(bar);");
  L.push("ta = document.createElement('textarea');");
  L.push("ta.readOnly = true;");
  L.push("ta.style.cssText = 'width:100%;height:320px;background:#000;color:#0f0;font:11px monospace;border:1px solid #444;';");
  L.push("panel.appendChild(ta);");
  L.push("document.body.appendChild(panel);");
  L.push("document.body.appendChild(badge);");
  L.push("var toggle = function(){ panel.style.display = panel.style.display === 'none' ? 'block' : 'none'; refresh(); };");
  L.push("if (badge.attachEvent) { badge.attachEvent('onclick', toggle); } else { badge.addEventListener('click', toggle, false); }");
  L.push("refresh(); }");
  L.push("function hookAjax(){ try { if (window.jQuery && window.jQuery.fn) { jQuery(document).ajaxError(function(ev, xhr, settings, err){ push('AJAXERROR', (settings ? settings.url : '?') + ' status=' + (xhr ? xhr.status : '?') + ' ' + (err || '')); }); push('PROBE', 'jQuery=' + jQuery.fn.jquery + ' migrate=' + (jQuery.migrateVersion || 'none')); } else { push('PROBE', 'jQuery not present'); } } catch(e) { push('PROBE', 'ajax hook failed: ' + e.message); } }");
  L.push("function onReady(){ buildPanel(); hookAjax(); refresh(); }");
  L.push("if (document.readyState === 'complete' || document.readyState === 'interactive') { window.setTimeout(onReady, 200); } else if (window.addEventListener) { window.addEventListener('load', onReady, false); } else if (window.attachEvent) { window.attachEvent('onload', onReady); }");
  L.push("push('PROBE', MARKER + ' loaded');");
  L.push("})();");
  return L.join("\n");
}
function findingRow(f) {
  return [f.abs, f.rel, fileNameOf(f.rel), f.line, f.category, f.pattern, f.priority, f.confidence, f.action, f.before, f.after || f.suggestion, f.reason, f.lib, f.thirdParty, f.commitGroup];
}
const FINDING_HEADER = ["FilePath", "RelativePath", "FileName", "LineNumber", "Category", "Pattern", "Priority", "Confidence", "Action", "Before", "After", "Reason", "LibraryGuess", "ThirdParty", "CommitGroup"];

function writeCsvReports(model) {
  const R = model.reportRoot;
  ensureDir(R);
  const cnt = model.counters;
  writeCsv(path.join(R, "summary.csv"), ["Key", "Value"], Object.keys(cnt).map(function (k) { return [k, cnt[k]]; }));
  writeCsv(path.join(R, "apiFindings.csv"), FINDING_HEADER, model.findings.map(findingRow));
  writeCsv(path.join(R, "critical.csv"),
    ["FilePath", "RelativePath", "LineNumber", "OldSrc", "Version", "Recommendation"],
    model.oldCoreRefs.map(function (r) {
      return [r.ctx.abs, r.page, r.line, r.raw, r.meta.ver, "replace with " + model.profile.jquery.coreFile + " + " + model.profile.jquery.migrateFile + " (patch-jquery mode)"];
    }));
  writeCsv(path.join(R, "focusQueue.csv"),
    ["Rank", "RelativePath", "LineNumber", "Category", "Priority", "Confidence", "Pattern", "Reason", "Suggestion"],
    model.focus.map(function (f, i) { return [i + 1, f.rel, f.line, f.category, f.priority, f.confidence, f.pattern, f.reason, f.suggestion || f.after]; }));
  writeCsv(path.join(R, "manualQueue.csv"), FINDING_HEADER,
    model.findings.filter(function (f) { return (f.priority === "Manual" || f.priority === "Review") && f.thirdParty !== "Y"; }).map(findingRow));
  writeCsv(path.join(R, "autoFixed.csv"), FINDING_HEADER,
    model.findings.filter(function (f) { return (f.priority === "AutoFixed" || f.priority === "AutoFixed2") && f.action === "Changed"; }).map(findingRow));
  writeCsv(path.join(R, "vendorReview.csv"), FINDING_HEADER,
    model.findings.filter(function (f) { return f.priority === "VendorReview"; }).map(findingRow));
  writeCsv(path.join(R, "xssHigh.csv"), FINDING_HEADER,
    model.findings.filter(function (f) { return f.priority === "XssHigh"; }).map(findingRow));
  writeCsv(path.join(R, "staticHtmlLow.csv"), FINDING_HEADER,
    model.findings.filter(function (f) { return f.priority === "StaticHtmlLow"; }).map(findingRow));
  writeCsv(path.join(R, "jqueryLoads.csv"),
    ["PagePath", "LineNumber", "ScriptSrcRaw", "ScriptSrcResolved", "Library", "Version", "IsOldBelow350", "Resolved"],
    model.jqueryLoadRows.map(function (r) {
      return [r.page, r.line, r.raw, r.resolved, r.meta.isMigrate ? "jquery-migrate" : "jquery-core", r.meta.ver, r.meta.isOld ? "Y" : "N", r.exists ? "Y" : "N"];
    }));
  writeCsv(path.join(R, "scriptInventory.csv"), ["RelativePath", "LibraryGuess", "VersionGuess", "IsVendor", "IsMinified", "RiskNote"], model.scriptInv);
  writeCsv(path.join(R, "pluginInventory.csv"), ["RelativePath", "LibraryGuess", "VersionGuess", "Evidence", "RiskLevel", "Recommendation"], model.pluginInv);
  writeCsv(path.join(R, "directoryInventory.csv"), ["RelativePath", "Type", "Extension", "Size", "LibraryGuess", "IsVendor", "IsPage", "IsScript", "IsStyle"], model.dirInv);
  writeCsv(path.join(R, "jspPages.csv"),
    ["PagePath", "DirectScriptCount", "EffectiveScriptCount", "DirectCssCount", "EffectiveCssCount", "HasJqueryCore", "JqueryCoreCount", "JqueryCoreVersion", "HasOldJqueryBelow350", "HasMigrate", "MigrateAfterJquery", "RiskMultipleJquery", "RiskOldJquery", "RiskMigrateMissing"],
    model.pages.map(function (p) {
      return [p.rel, p.directScripts, p.effectiveScripts, p.directCss, p.effectiveCss, p.hasCore ? "Y" : "N", p.coreCount, p.coreVer, p.oldCore ? "Y" : "N", p.hasMigrate ? "Y" : "N", p.migrateAfter, p.riskMultiCore ? "Y" : "N", p.riskOldCore ? "Y" : "N", p.riskMigrateMissing ? "Y" : "N"];
    }));
  writeCsv(path.join(R, "jspIncludes.csv"),
    ["ParentPage", "IncludeType", "IncludeTargetRaw", "IncludeTargetResolved", "Resolved", "Reason"],
    model.includeRows.map(function (r) { return [r.page, r.type, r.raw, r.resolved, r.ok ? "Y" : "N", r.reason]; }));
  writeCsv(path.join(R, "pageScriptMap.csv"),
    ["PagePath", "LineNumber", "ScriptSrcRaw", "ScriptSrcResolved", "LibraryGuess", "VersionGuess", "IsJqueryCore", "IsOldJqueryBelow350", "IsMigrate", "Resolved"],
    model.pageScriptRows.map(function (r) {
      return [r.page, r.line, r.raw, r.resolved, r.meta.lib, r.meta.ver, r.meta.isCore ? "Y" : "N", r.meta.isOld ? "Y" : "N", r.meta.isMigrate ? "Y" : "N", r.exists ? "Y" : "N"];
    }));
  writeCsv(path.join(R, "pageScriptEffective.csv"),
    ["PagePath", "SourcePage", "ScriptSrcRaw", "ScriptSrcResolved", "EffectiveOrder", "LibraryGuess", "VersionGuess", "IsJqueryCore", "IsOldJqueryBelow350", "IsMigrate"],
    model.effectiveRows.map(function (r) {
      return [r.page, r.srcPage, r.raw, r.resolved, r.order, r.lib, r.ver, r.isCore ? "Y" : "N", r.isOld ? "Y" : "N", r.isMigrate ? "Y" : "N"];
    }));
  writeCsv(path.join(R, "pageCssMap.csv"),
    ["PagePath", "LineNumber", "CssHrefRaw", "CssHrefResolved", "LibraryGuess", "VersionGuess", "Resolved"],
    model.pageCssRows.map(function (r) { return [r.page, r.line, r.raw, r.resolved, r.lib, r.ver, r.exists ? "Y" : "N"]; }));
  writeCsv(path.join(R, "unresolvedRefs.csv"), ["PagePath", "RefType", "RawRef", "Reason"],
    model.unresolvedRows.map(function (r) { return [r.page, r.type, r.raw, r.reason]; }));
  writeCsv(path.join(R, "ajaxEndpoints.csv"),
    ["RelativePath", "LineNumber", "MethodGuess", "UrlRaw", "UrlNormalized", "Dynamic", "Confidence", "MockRecommendation"],
    model.ajaxRows.map(function (r) { return [r.rel, r.line, r.method, r.urlRaw, r.urlNorm, r.dynamic, r.confidence, r.mock]; }));
  writeCsv(path.join(R, "jsSyntax.csv"), ["RelativePath", "Result", "Reason"],
    model.syntaxRows.map(function (r) { return [r.rel, r.result, r.reason]; }));
  writeCsv(path.join(R, "completeByAutoFix.csv"),
    ["RelativePath", "Result", "TotalFindings", "AutoFixed", "AutoFixed2", "StaticHtmlLow", "Critical", "Manual", "Review", "XssHigh", "VendorReview", "Reason"],
    model.completeRows);
  writeCsv(path.join(R, "needsWorkByFile.csv"),
    ["RelativePath", "Critical", "XssHigh", "Manual", "Review", "VendorReview", "Categories"],
    model.needsRows);
  writeCsv(path.join(R, "changedFiles.csv"), ["RelativePath", "ProjectRelativePath", "EditCount", "Kind"],
    Object.keys(model.changed).sort().map(function (rel) {
      const c = model.changed[rel];
      return [rel, c.projRel, c.edits, c.kind];
    }));
  if (model.probeInjections.length > 0) {
    writeCsv(path.join(R, "probe_injection_map.csv"), ["PagePath", "Result", "Detail"], model.probeInjections);
  }
  if (model.patchResults.length > 0) {
    writeUtf8(path.join(R, "patch_jquery_result.txt"),
      model.patchResults.map(function (r) { return r[2] + "\t" + r[0] + "\t" + r[1] + "\t" + r[3]; }).join("\r\n") + "\r\n", true);
  }
}

function xlsCell(v) {
  const s = String(v == null ? "" : v);
  const isNum = /^-?\d+(\.\d+)?$/.test(s) && s.length < 15;
  return '<Cell><Data ss:Type="' + (isNum ? "Number" : "String") + '">' + xmlEsc(s) + "</Data></Cell>";
}
function xlsSheet(name, header, rows) {
  const out = ['<Worksheet ss:Name="' + xmlEsc(name.slice(0, 31)) + '"><Table>'];
  out.push("<Row>" + header.map(function (h) { return '<Cell ss:StyleID="hdr"><Data ss:Type="String">' + xmlEsc(h) + "</Data></Cell>"; }).join("") + "</Row>");
  rows.forEach(function (r) { out.push("<Row>" + r.map(xlsCell).join("") + "</Row>"); });
  out.push("</Table></Worksheet>");
  return out.join("\n");
}
function writeXls(model) {
  const cnt = model.counters;
  const sheets = [];
  sheets.push(xlsSheet("Summary", ["Key", "Value"], Object.keys(cnt).map(function (k) { return [k, cnt[k]]; })));
  sheets.push(xlsSheet("FocusQueue", ["Rank", "RelativePath", "Line", "Category", "Priority", "Reason", "Suggestion"],
    model.focus.slice(0, 2000).map(function (f, i) { return [i + 1, f.rel, f.line, f.category, f.priority, f.reason, f.suggestion || f.after]; })));
  sheets.push(xlsSheet("Critical", ["RelativePath", "Line", "OldSrc", "Version"],
    model.oldCoreRefs.map(function (r) { return [r.page, r.line, r.raw, r.meta.ver]; })));
  sheets.push(xlsSheet("ApiFindings", FINDING_HEADER.slice(1), model.findings.slice(0, 5000).map(function (f) { return findingRow(f).slice(1); })));
  sheets.push(xlsSheet("JspPages", ["PagePath", "EffScripts", "CoreCount", "CoreVer", "OldCore", "Migrate", "MigrateAfter"],
    model.pages.slice(0, 2000).map(function (p) { return [p.rel, p.effectiveScripts, p.coreCount, p.coreVer, p.oldCore ? "Y" : "N", p.hasMigrate ? "Y" : "N", p.migrateAfter]; })));
  sheets.push(xlsSheet("PluginInventory", ["RelativePath", "Library", "Version", "RiskLevel", "Recommendation"],
    model.pluginInv.slice(0, 1000).map(function (r) { return [r[0], r[1], r[2], r[4], r[5]]; })));
  const doc = ['<?xml version="1.0" encoding="UTF-8"?>',
    '<?mso-application progid="Excel.Sheet"?>',
    '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet">',
    '<Styles><Style ss:ID="hdr"><Font ss:Bold="1"/><Interior ss:Color="#DDDDDD" ss:Pattern="Solid"/></Style></Styles>',
    sheets.join("\n"),
    "</Workbook>"].join("\n");
  writeUtf8(path.join(model.reportRoot, "jquery35_report.xls"), doc, false);
}

function kpiCard(label, value, color) {
  return '<div class="card" style="border-top:4px solid ' + color + '"><div class="v">' + htmlEsc(value) + '</div><div class="l">' + htmlEsc(label) + "</div></div>";
}
function reportLink(file, label) {
  return '<a href="' + htmlEsc(file) + '">' + htmlEsc(label || file) + "</a>";
}
function tableHtml(header, rows) {
  let h = "<table><thead><tr>";
  header.forEach(function (x) { h += "<th>" + htmlEsc(x) + "</th>"; });
  h += "</tr></thead><tbody>";
  rows.forEach(function (r) {
    h += "<tr>";
    r.forEach(function (c) { h += "<td>" + htmlEsc(c) + "</td>"; });
    h += "</tr>";
  });
  return h + "</tbody></table>";
}
function scriptJson(v) {
  return JSON.stringify(v).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}
function snippetRows(text, line, contextLines) {
  const lines = String(text || "").split("\n");
  let center = parseInt(line, 10);
  if (!Number.isFinite(center) || center < 1) center = 1;
  const lo = Math.max(1, center - contextLines);
  const hi = Math.min(lines.length, center + contextLines);
  const out = [];
  for (let ln = lo; ln <= hi; ln++) {
    out.push({ n: ln, hit: ln === center, text: trunc(String(lines[ln - 1] || "").replace(/\r$/, ""), 500) });
  }
  return out;
}
function snippetFromRoot(root, rel, line, contextLines, missingNote) {
  if (!root) return { available: false, note: missingNote || "not available", rows: [] };
  const abs = path.join(root, toPosix(rel).split("/").join(path.sep));
  if (!exists(abs)) return { available: false, note: "file not found: " + rel, rows: [] };
  return { available: true, note: "", rows: snippetRows(readLatin1(abs), line, contextLines) };
}
function verificationHint(model, f) {
  if (f.priority === "Critical" || f.category === "jquery-core-old") return "jQuery " + model.profile.jquery.targetVersion + "과 Migrate 파일 존재, core -> migrate 로드 순서, 중복 core 로드 여부, 주요 화면 JQMIGRATE/JS error를 확인하세요.";
  if (f.priority === "XssHigh" || f.category === "dom-sink" || f.category === "wrapper-dom-sink") return "값 출처가 서버/사용자 입력인지 확인하고, HTML이 필요 없으면 .text(), 필요하면 escape/sanitizer와 신뢰 경계를 확인하세요.";
  if (f.category.indexOf("bool-attr") === 0) return "변수 값 도메인(Y/N, true/false, 1/0 등)과 disabled/checked/readonly 동작이 기존 화면과 같은지 확인하세요.";
  if (f.category === "jqxhr-shorthand") return "이 호출이 AJAX 콜백인지 DOM/다른 객체 메서드인지 확인하고, 성공/실패 콜백 인자의 출처를 확인하세요.";
  if (f.category === "live-die") return "동적으로 추가되는 요소 이벤트라면 .on(event, selector, handler) 위임 방식으로 바꾼 뒤 이벤트가 계속 동작하는지 확인하세요.";
  if (f.category === "jquery-core-unknown") return "파일 배너/실제 배포 파일에서 jQuery 버전을 확인하고 3.5 미만이면 patch-jquery 대상에 포함하세요.";
  return "AS-IS/TO-BE 차이를 확인하고 해당 화면에서 기존 동작, JS error, JQMIGRATE warning 여부를 확인하세요.";
}
function changePlanText(model, f) {
  if (f.action === "Changed") return "자동수정 적용/예정: " + trunc(f.before || f.pattern, 120) + " -> " + trunc(f.after || f.suggestion || "", 160);
  if (f.suggestion || f.after) return "권장 조치: " + trunc(f.suggestion || f.after, 220);
  if (f.priority === "Critical") return "patch-jquery 모드에서 jQuery core script src를 " + model.profile.jquery.targetVersion + " + Migrate 조합으로 교체합니다.";
  if (f.priority === "XssHigh") return "자동수정 금지. 값 출처와 HTML 필요 여부를 확인한 뒤 .text()/escape/sanitizer 중 하나로 수동 조치하세요.";
  return "자동 변경하지 않습니다. 코드 의도를 확인한 뒤 수동 조치 또는 project-profile 학습 규칙으로 분류를 보정하세요.";
}
const FOCUS_STAGE_ORDER = [
  { key: "min", title: "1차 최소", badge: "취약점 통과", tone: "danger", desc: "이 단계는 먼저 봅니다. 구버전 jQuery 참조와 버전 불명 core를 정리해 3.5.1 안착 기준을 맞춥니다." },
  { key: "compat", title: "2차 안정화", badge: "깨짐 방지", tone: "warn", desc: "3.5.1에서 화면 오류로 이어질 가능성이 큰 업무 코드입니다. 주요 화면 테스트와 같이 봅니다." },
  { key: "max", title: "3차 최대/후속", badge: "장기 정리", tone: "calm", desc: "이번 배포 필수 범위 밖의 보안/유지보수 부채입니다. 일정이 있을 때 확장합니다." }
];
function focusStageKey(f) {
  if (f.priority === "Critical" || f.category === "jquery-core-old" || f.category === "jquery-core-unknown") return "min";
  if (f.priority === "XssHigh") return "max";
  if (f.category === "dom-sink" || f.category === "dom-factory" || f.category === "parse-html" || f.category === "wrapper-dom-sink" || f.category === "trim-deprecated") return "max";
  return "compat";
}
function buildFocusDetails(model) {
  const hasTarget = model.targetWcRoot && isDir(model.targetWcRoot);
  return model.focus.slice(0, 100).map(function (f, i) {
    const ctx = model.ctxByRel[f.rel];
    const line = f.line || (ctx ? lineOf(ctx.lineStarts, f.idx || 0) : 1);
    return {
      rank: i + 1, modalIndex: i, stage: focusStageKey(f), rel: f.rel, line: line, category: f.category, priority: f.priority,
      confidence: f.confidence, action: f.action, pattern: f.pattern,
      reason: f.reason, change: changePlanText(model, f), verify: verificationHint(model, f),
      asIs: ctx ? { available: true, note: "", rows: snippetRows(ctx.text, line, 5) } : snippetFromRoot(model.webContentRoot, f.rel, line, 5, "source not available"),
      toBe: snippetFromRoot(hasTarget ? model.targetWcRoot : "", f.rel, line, 5, hasTarget ? "TO-BE file not available" : "TO-BE not generated in this mode")
    };
  });
}
function focusQueueHtml(model, details) {
  let h = "";
  FOCUS_STAGE_ORDER.forEach(function (stage) {
    const group = details.filter(function (d) { return d.stage === stage.key; });
    h += '<div class="stageFocus ' + stage.tone + '"><div class="stageHead"><div><b>' + htmlEsc(stage.title) + '</b><span>' + htmlEsc(stage.badge) + '</span></div><strong>' + group.length + '</strong></div><div class="small">' + htmlEsc(stage.desc) + "</div>";
    if (group.length === 0) {
      h += '<div class="emptyQueue">이 단계에 표시할 FocusQueue 항목이 없습니다.</div></div>';
      return;
    }
    h += "<table><thead><tr><th>순위</th><th>파일</th><th>라인</th><th>유형</th><th>우선순위</th><th>사유</th></tr></thead><tbody>";
    group.forEach(function (d) {
      h += "<tr><td>" + d.rank + '</td><td><button type="button" class="filelink" onclick="openFocusDetail(' + d.modalIndex + ')">' + htmlEsc(d.rel) + "</button></td><td>" + htmlEsc(d.line) + "</td><td>" + htmlEsc(d.category) + "</td><td>" + htmlEsc(d.priority) + "</td><td>" + htmlEsc(d.reason) + "</td></tr>";
    });
    h += "</tbody></table></div>";
  });
  return h;
}

function findCount(model, fn) {
  let n = 0;
  model.findings.forEach(function (f) { if (fn(f)) n++; });
  return n;
}
function isCompatMinimalFinding(f) {
  if (f.thirdParty === "Y") return false;
  if (f.priority === "Critical") return false;
  if (f.category === "jqxhr-shorthand" || f.category === "live-die" || f.category === "jquery-browser") return true;
  if (f.category === "event-shortcut-load" || f.category === "size-to-length" || f.category === "andself-to-addback") return true;
  if (f.category.indexOf("bool-attr") === 0) return true;
  return false;
}
function isDeferredMaxFinding(f) {
  if (f.thirdParty === "Y") return false;
  if (f.priority === "XssHigh") return true;
  if (f.category === "trim-deprecated" || f.category === "parse-html" || f.category === "dom-sink" || f.category === "dom-factory" || f.category === "wrapper-dom-sink") return true;
  return false;
}
function buildScopeRows(model) {
  const c = model.counters;
  const coreUnknown = findCount(model, function (f) { return f.category === "jquery-core-unknown"; });
  const minCount = c.Gate35Blockers + coreUnknown + c.PageRiskMultipleJqueryCore + c.PageRiskMigrateMissing + c.PageRiskMigrateBeforeCore;
  const compatCount = findCount(model, isCompatMinimalFinding);
  const safeAuto = c.AutoFixed + c.AutoFixed2;
  const maxCount = findCount(model, isDeferredMaxFinding) + c.VendorReview;
  return [
    {
      key: "min", title: "1차 최소", badge: "취약점 통과", tone: "danger", count: minCount,
      goal: "jQuery core를 " + c.JqueryTargetVersion + "로 교체하고 " + c.JqueryFloorVersion + " 미만 참조를 0건으로 만듭니다.",
      doText: "patch-jquery, Migrate 로드 순서, 중복 core, verify-clean FAIL 제거",
      stop: "verify-clean에서 old-jquery-refs / critical-findings / probe-leftover FAIL이 0건이면 1차 목표는 충족",
      files: [reportLink("critical.csv", "critical.csv"), reportLink("jqueryLoads.csv", "jqueryLoads.csv"), reportLink("jspPages.csv", "jspPages.csv"), reportLink("pageScriptEffective.csv", "pageScriptEffective.csv")]
    },
    {
      key: "compat", title: "2차 안정화", badge: "깨짐 방지", tone: "warn", count: safeAuto + compatCount,
      goal: "3.5.1에서 실제 오류가 나기 쉬운 업무 코드만 우선 정리합니다.",
      doText: ".size(), .load(), jqXHR success/error/complete, live/die, boolean attr, $.browser 후보 확인",
      stop: "주요 화면 JS error 0건이고 업무 플로우가 깨지지 않으면 다음 업무로 넘어가도 됩니다.",
      files: [reportLink("autoFixed.csv", "autoFixed.csv"), reportLink("manualQueue.csv", "manualQueue.csv"), reportLink("focusQueue.csv", "focusQueue.csv"), reportLink("runtime_test_checklist.txt", "runtime_test_checklist.txt")]
    },
    {
      key: "max", title: "3차 최대/후속", badge: "장기 정리", tone: "calm", count: maxCount,
      goal: "이번 배포 필수는 아니지만 보안·유지보수 부채를 줄이는 범위입니다.",
      doText: "DOM XSS 후보, 벤더 라이브러리 교체, Migrate warning 0건, jQuery 4 대비 deprecated 정리",
      stop: "Migrate 제거 또는 jQuery 4 대비까지 목표일 때만 이 단계까지 확장",
      files: [reportLink("xssHigh.csv", "xssHigh.csv"), reportLink("vendorReview.csv", "vendorReview.csv"), reportLink("staticHtmlLow.csv", "staticHtmlLow.csv"), reportLink("pluginInventory.csv", "pluginInventory.csv")]
    }
  ];
}
function scopeRoadmapHtml(model) {
  const rows = buildScopeRows(model);
  let h = '<div class="scopeGrid">';
  rows.forEach(function (r) {
    h += '<div class="scopeCard ' + r.tone + '"><div class="scopeTop"><div><div class="scopeTitle">' + htmlEsc(r.title) + '</div><div class="scopeBadge">' + htmlEsc(r.badge) + '</div></div><div class="scopeCount">' + htmlEsc(r.count) + '</div></div><div class="scopeGoal">' + htmlEsc(r.goal) + '</div><div class="scopeLine"><b>할 일</b><br>' + htmlEsc(r.doText) + '</div><div class="scopeLine"><b>멈춤 기준</b><br>' + htmlEsc(r.stop) + '</div></div>';
  });
  h += "</div>";
  h += '<div class="reportLinks"><b>상세 파일</b> ';
  h += uniq(rows.reduce(function (acc, r) { return acc.concat(r.files); }, [])).join(" / ");
  h += "</div>";
  return h;
}
function writeIndexHtml(model) {
  const c = model.counters;
  const focusDetails = buildFocusDetails(model);
  const parts = [];
  parts.push("<!DOCTYPE html><html lang=\"ko\"><head><meta charset=\"utf-8\"><title>jQuery 3.5 조치 보고서</title><style>");
  parts.push("body{font-family:'Malgun Gothic',AppleGothic,sans-serif;margin:20px;background:#f5f6f8;color:#222}h1{font-size:20px}h2{font-size:16px;margin-top:28px;border-left:4px solid #3b6fd4;padding-left:8px}");
  parts.push(".cards{display:flex;flex-wrap:wrap;gap:10px}.card{background:#fff;border:1px solid #ddd;border-radius:6px;padding:10px 16px;min-width:120px}.card .v{font-size:22px;font-weight:bold}.card .l{font-size:12px;color:#666}");
  parts.push("table{border-collapse:collapse;background:#fff;font-size:12px;margin-top:8px;width:100%}th,td{border:1px solid #ddd;padding:4px 8px;text-align:left;word-break:break-all}th{background:#eef1f6}");
  parts.push(".warn{color:#b26a00}.crit{color:#b00020;font-weight:bold}.ok{color:#1b5e20}.small{font-size:12px;color:#555}");
  parts.push("a{color:#174ea6}.scopeGrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:10px}.scopeCard{background:#fff;border:1px solid #ddd;border-top:4px solid #78909c;border-radius:6px;padding:12px;min-height:168px}.scopeCard.danger{border-top-color:#b00020}.scopeCard.warn{border-top-color:#b26a00}.scopeCard.calm{border-top-color:#546e7a}.scopeTop{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.scopeTitle{font-size:15px;font-weight:bold}.scopeBadge{display:inline-block;margin-top:4px;padding:2px 7px;border:1px solid #ddd;border-radius:999px;font-size:11px;color:#555;background:#f8f9fb}.scopeCount{font-size:28px;font-weight:bold;line-height:1}.scopeGoal{margin-top:10px;font-size:12px;color:#333}.scopeLine{margin-top:9px;font-size:12px;color:#555}.reportLinks{margin-top:8px;background:#fff;border:1px solid #ddd;padding:8px 10px;font-size:12px}@media(max-width:1000px){.scopeGrid{grid-template-columns:1fr}}");
  parts.push(".stageFocus{background:#fff;border:1px solid #ddd;border-left:4px solid #78909c;margin-top:12px;padding:10px}.stageFocus.danger{border-left-color:#b00020}.stageFocus.warn{border-left-color:#b26a00}.stageFocus.calm{border-left-color:#546e7a}.stageHead{display:flex;align-items:center;justify-content:space-between;gap:12px}.stageHead b{font-size:14px}.stageHead span{margin-left:8px;font-size:11px;color:#666;border:1px solid #ddd;border-radius:999px;padding:2px 7px;background:#f8f9fb}.stageHead strong{font-size:22px}.emptyQueue{margin-top:8px;border:1px dashed #ccc;background:#fafafa;color:#666;font-size:12px;padding:10px}");
  parts.push("details{background:#fff;border:1px solid #ddd;margin-top:12px;padding:8px 10px}summary{cursor:pointer;font-weight:bold}.detailBlock{margin-top:10px}");
  parts.push(".filelink{border:0;background:transparent;color:#174ea6;text-decoration:underline;cursor:pointer;font:inherit;text-align:left;padding:0}.modalBackdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:1000;display:none}.modalBox{position:absolute;inset:4%;background:#fff;border:1px solid #444;box-shadow:0 12px 40px rgba(0,0,0,.35);display:flex;flex-direction:column}.modalHead{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid #ddd;background:#eef1f6}.modalTitle{font-weight:bold}.modalClose{border:1px solid #999;background:#fff;padding:3px 10px;cursor:pointer}.modalBody{padding:12px;overflow:auto}.detailGrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.infoGrid{display:grid;grid-template-columns:130px 1fr;gap:4px 10px;font-size:12px;margin-bottom:12px}.infoGrid div:nth-child(odd){font-weight:bold;color:#555}.pane{border:1px solid #ddd;background:#fafafa}.pane h3{font-size:13px;margin:0;padding:6px 8px;background:#f0f0f0;border-bottom:1px solid #ddd}.codeLine{display:grid;grid-template-columns:46px 1fr;font:12px/1.45 Consolas,Menlo,monospace;white-space:pre-wrap}.codeLine .ln{color:#777;text-align:right;padding:0 8px;border-right:1px solid #e0e0e0;user-select:none}.codeLine .txt{padding:0 8px}.codeLine.hit{background:#fff3cd}.noteBox{font:12px Consolas,Menlo,monospace;padding:10px;color:#666}@media(max-width:900px){.detailGrid{grid-template-columns:1fr}.modalBox{inset:2%}}");
  parts.push("</style></head><body>");
  parts.push("<h1>jQuery " + CVE_ID + " 조치 보고서 (" + TOOL_NAME + " v" + TOOL_VERSION + ")</h1>");
  parts.push('<div class="small">Mode: ' + htmlEsc(c.Mode) + " / jQuery target: " + htmlEsc(c.JqueryTargetVersion) + " / pass floor: " + htmlEsc(c.JqueryFloorVersion) + " / Source: " + htmlEsc(c.SourceRoot) + " / WebContent: " + htmlEsc(c.WebContentRoot) + " / Target: " + htmlEsc(c.TargetRoot) + "</div>");
  parts.push('<h2>요약</h2><div class="cards">');
  parts.push(kpiCard("3.5 게이트", c.Gate35Blockers, "#b00020"));
  parts.push(kpiCard("자동수정", c.AutoFixed + c.AutoFixed2, "#1b5e20"));
  parts.push(kpiCard("FocusQueue", c.FocusQueue, "#6a1b9a"));
  parts.push(kpiCard("수동/검토", c.Manual + c.Review, "#b26a00"));
  parts.push(kpiCard("XSS 고위험", c.XssHigh, "#b00020"));
  parts.push(kpiCard("벤더 검토", c.VendorReview, "#546e7a"));
  parts.push("</div>");
  parts.push("<h2>조치 범위 로드맵</h2>");
  parts.push(scopeRoadmapHtml(model));
  parts.push("<h2>단계별 FocusQueue (상위 100건)</h2>");
  parts.push('<div class="small">1차 최소부터 확인하세요. 파일명을 클릭하면 AS-IS/TO-BE 주변 코드, 판단 사유, 권장 조치, 확인 포인트가 모달로 열립니다.</div>');
  parts.push(focusQueueHtml(model, focusDetails));
  parts.push("<details><summary>상세 표 펼치기</summary><div class=\"detailBlock\">");
  parts.push("<h2>1차 상세: " + TARGET_JQUERY_FLOOR_VERSION + " 미만 jQuery core 호출부 (" + model.oldCoreRefs.length + "건)</h2>");
  parts.push(tableHtml(["페이지", "라인", "src", "버전"], model.oldCoreRefs.map(function (r) { return [r.page, r.line, r.raw, r.meta.ver]; })));
  parts.push('<div class="small">이 항목은 plan/autofix에서는 자동 변경되지 않습니다. ' + htmlEsc(model.profile.jquery.coreFile) + " / " + htmlEsc(model.profile.jquery.migrateFile) + ' 파일을 WebContent/js에 넣은 뒤 patch-jquery 모드로 교체하세요.</div>');
  parts.push("<h2>페이지 리스크</h2>");
  const riskPages = model.pages.filter(function (p) { return p.riskMultiCore || p.riskOldCore || p.riskMigrateMissing || p.riskMigrateBeforeCore; });
  parts.push(tableHtml(["페이지", "core 수", "버전", "구버전", "Migrate", "Migrate 순서"],
    riskPages.map(function (p) { return [p.rel, p.coreCount, p.coreVer, p.oldCore ? "Y" : "", p.hasMigrate ? "Y" : "누락", p.migrateAfter]; })));
  parts.push("<h2>라이브러리 분포</h2>");
  let lc = {};
  try { lc = JSON.parse(c.LibraryCounts); } catch (e) { }
  parts.push(tableHtml(["라이브러리", "JS 파일 수"], Object.keys(lc).map(function (k) { return [k, lc[k]]; })));
  if (model.reviewCasesAll > 0) {
    parts.push("<h2>AI 리뷰팩 (애매한 코드 " + model.reviewCasesAll + "그룹 중 상위 " + model.reviewCases.length + "건)</h2>");
    parts.push(tableHtml(["CaseId", "종류", "이름", "호출부수", "건수", "현재분류", "질문"],
      model.reviewCases.slice(0, 20).map(function (g) {
        return [g.caseId, g.kind === "FN" ? "함수" : "패턴", g.name, g.fanout, g.count, g.findings[0].priority, trunc(g.question, 60)];
      })));
    parts.push('<div class="small">--mode review-pack 실행 시 ai_review_pack.txt/json이 생성됩니다. 코드 원문 없이 함수명/앞뒤 몇 줄만 담겨 외부 AI에게 전달 가능하며, 답변을 project-profile.json에 병합하면 다음 라운드에 자동 반영됩니다.</div>');
  }
  parts.push("<h2>다음 액션</h2><ol>");
  recommendedActions(model).forEach(function (a) { parts.push("<li>" + htmlEsc(a) + "</li>"); });
  parts.push("</ol></div></details>");
  parts.push('<div class="small">상세 데이터: apiFindings.csv / focusQueue.csv / jspPages.csv / pageScriptEffective.csv / jquery35_report.xls</div>');
  parts.push('<div id="focusDetailModal" class="modalBackdrop" onclick="if(event.target===this) closeFocusDetail();"><div class="modalBox"><div class="modalHead"><div id="focusModalTitle" class="modalTitle"></div><button type="button" class="modalClose" onclick="closeFocusDetail()">Close</button></div><div class="modalBody"><div id="focusModalInfo" class="infoGrid"></div><div class="detailGrid"><div class="pane"><h3>AS-IS</h3><div id="focusAsIs"></div></div><div class="pane"><h3>TO-BE</h3><div id="focusToBe"></div></div></div></div></div></div>');
  parts.push("<script>window.__JQ35_FOCUS_DETAILS__=" + scriptJson(focusDetails) + ";\n(function(){function esc(s){return String(s==null?'':s).replace(/[&<>\\\"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','\\\"':'&quot;'}[c];});}function block(sn){if(!sn||!sn.available){return '<div class=\"noteBox\">'+esc(sn&&sn.note?sn.note:'not available')+'</div>';}return sn.rows.map(function(r){return '<div class=\"codeLine '+(r.hit?'hit':'')+'\"><span class=\"ln\">'+esc(r.n)+'</span><span class=\"txt\">'+esc(r.text)+'</span></div>';}).join('');}window.openFocusDetail=function(i){var d=window.__JQ35_FOCUS_DETAILS__[i];if(!d)return;document.getElementById('focusModalTitle').textContent='#'+d.rank+' '+d.rel+':'+d.line;document.getElementById('focusModalInfo').innerHTML='<div>유형</div><div>'+esc(d.category)+' / '+esc(d.priority)+' / '+esc(d.confidence)+'</div><div>패턴</div><div>'+esc(d.pattern)+'</div><div>왜 문제인가</div><div>'+esc(d.reason)+'</div><div>어떻게 바꾸나</div><div>'+esc(d.change)+'</div><div>확인할 것</div><div>'+esc(d.verify)+'</div>';document.getElementById('focusAsIs').innerHTML=block(d.asIs);document.getElementById('focusToBe').innerHTML=block(d.toBe);document.getElementById('focusDetailModal').style.display='block';};window.closeFocusDetail=function(){document.getElementById('focusDetailModal').style.display='none';};document.addEventListener('keydown',function(e){if(e.key==='Escape')closeFocusDetail();});})();</script>");
  parts.push("</body></html>");
  writeUtf8(path.join(model.reportRoot, "index.html"), parts.join("\n"), false);
}

function recommendedActions(model) {
  const c = model.counters;
  const out = [];
  if (c.Critical > 0) out.push("jQuery " + model.profile.jquery.targetVersion + " + Migrate " + model.profile.jquery.migrateVersion + " 파일을 WebContent/js에 배치한 뒤 patch-jquery 모드로 " + c.Critical + "개 호출부를 교체 (CVE-2020-11023 핵심 조치)");
  if (c.AutoFixed + c.AutoFixed2 > 0) out.push("autofix 결과 TO-BE와 원본을 WinMerge/Eclipse Compare로 비교 후 안전 자동수정 " + (c.AutoFixed + c.AutoFixed2) + "건을 브랜치에 반영");
  if (c.Manual > 0) out.push("manualQueue.csv의 수동 조치 " + c.Manual + "건 처리 (.success/.error/.complete 전환, boolean attr 변수 타입 확인)");
  if (c.XssHigh > 0) out.push("XssHigh " + c.XssHigh + "건 DOM XSS 검토: .text()/escapeHtml 적용 또는 신뢰 경계 확인 (jQuery 업그레이드만으로는 미해결)");
  if (c.VendorReview > 0) out.push("벤더 라이브러리(jqGrid/jquery-ui/select2/autoNumeric)는 직접 수정하지 말고 Migrate 상태에서 화면 테스트 및 호환 버전 검토");
  if (c.PageRiskMigrateMissing > 0) out.push("Migrate 누락 페이지 " + c.PageRiskMigrateMissing + "건에 jquery-migrate 추가");
  if (c.Manual + c.Review > 5) out.push("review-pack 모드로 애매한 코드 지점(현재 " + c.ReviewCasesTotal + "그룹) 질문지를 뽑아 외부 AI와 반복 학습 (learnedWrappers/learnedFindings로 project-profile.json에 누적)");
  out.push("probe 모드로 Runtime Probe를 삽입해 Edge IE mode에서 JQMIGRATE 경고/JS 오류를 화면에서 수집");
  out.push("운영 반영 전 verify-clean 모드 실행 (probe 잔존/구버전 jQuery 잔존 시 FAIL)");
  return out;
}

function packetLines(model) {
  const c = model.counters;
  const includeSnippets = model.opts["include-snippets"] === true || model.opts["safe-packet"] === false;
  const L = [];
  L.push("JQUERY35_LOCAL_AGENT_PACKET v" + TOOL_VERSION);
  ["SourceRoot", "WebContentRoot", "TargetRoot", "ReportRoot", "Mode", "TotalFiles", "TextFiles", "PageFiles", "JsFiles",
    "JqueryTargetVersion", "JqueryFloorVersion", "Gate35Blockers",
    "ChangedFiles", "ApiFindings", "Critical", "AutoFixed", "AutoFixed2", "Review", "Manual", "XssHigh", "FocusQueue",
    "VendorReview", "StaticHtmlLow", "JqueryLoads", "OldJqueryBelow350", "PageRiskMultipleJqueryCore",
    "PageRiskOldJqueryCore", "PageRiskMigrateMissing", "PageRiskMigrateBeforeCore", "UnresolvedRefs", "AjaxEndpoints", "JsSyntaxFail",
    "ReviewCasesTotal", "ReviewCasesInPack", "LearnedWrapperCount", "LearnedFindingOverrides",
    "LibraryCounts", "GitInfo", "OldJquerySrcs"].forEach(function (k) {
      L.push(k + "=" + c[k]);
    });
  const fmtF = function (f) {
    let s = f.rel + ":" + f.line + ":" + f.category + ":" + f.priority;
    if (includeSnippets && f.before) s += " :: " + trunc(f.before, 100);
    return s;
  };
  L.push("");
  L.push("TopFocusQueue (" + Math.min(100, model.focus.length) + "/" + model.focus.length + "):");
  model.focus.slice(0, 100).forEach(function (f) { L.push("  " + fmtF(f)); });
  L.push("");
  L.push("TopCritical:");
  model.oldCoreRefs.slice(0, 20).forEach(function (r) { L.push("  " + r.page + ":" + r.line + ":" + r.raw + " (v" + r.meta.ver + ")"); });
  L.push("");
  L.push("TopManual:");
  model.findings.filter(function (f) { return f.priority === "Manual" && f.thirdParty !== "Y"; }).slice(0, 30).forEach(function (f) { L.push("  " + fmtF(f)); });
  L.push("");
  L.push("TopXssHigh:");
  model.findings.filter(function (f) { return f.priority === "XssHigh" && f.thirdParty !== "Y"; }).slice(0, 30).forEach(function (f) { L.push("  " + fmtF(f)); });
  L.push("");
  L.push("TopUnresolvedRefs:");
  model.unresolvedRows.slice(0, 15).forEach(function (r) { L.push("  " + r.page + ":" + r.type + ":" + r.raw + " (" + r.reason + ")"); });
  L.push("");
  L.push("TopAjaxEndpoints:");
  uniq(model.ajaxRows.map(function (r) { return r.method + " " + r.urlNorm; })).slice(0, 30).forEach(function (u) { L.push("  " + u); });
  L.push("");
  L.push("TopPluginInventory:");
  uniq(model.pluginInv.map(function (r) { return r[1] + (r[2] ? " v" + r[2] : ""); })).slice(0, 20).forEach(function (p) { L.push("  " + p); });
  L.push("");
  L.push("RecommendedNextActions:");
  recommendedActions(model).forEach(function (a, i) { L.push("  " + (i + 1) + ". " + a); });
  const cap = positiveIntOpt(model.opts["max-packet-lines"], 400);
  if (L.length > cap) {
    const kept = L.slice(0, cap - 1);
    kept.push("...(truncated " + (L.length - cap + 1) + " lines, adjust with --max-packet-lines)");
    return kept;
  }
  return L;
}

function writePacket(model) {
  writeUtf8(path.join(model.reportRoot, "assistant_packet.txt"), packetLines(model).join("\r\n") + "\r\n", true);
}

function writeChatSummary(model) {
  const c = model.counters;
  const L = [];
  L.push("jQuery CVE-2020-11023 조치 현황 요약 (" + TOOL_NAME + " v" + TOOL_VERSION + ", mode=" + c.Mode + ")");
  L.push("");
  L.push("대상: " + c.WebContentRoot);
  L.push("전체 " + c.TotalFiles + "개 파일 / 페이지 " + c.PageFiles + " / JS " + c.JsFiles);
  L.push("");
  L.push("핵심 수치");
  L.push("- 3.5 게이트(" + c.JqueryFloorVersion + " 미만 jQuery core 호출부): " + c.Gate35Blockers + "건 -> patch-jquery 모드로 " + c.JqueryTargetVersion + " 교체 (자동수정 아님)");
  L.push("- 안전 자동수정(AutoFixed): " + c.AutoFixed + "건 / 콜사이트 추론 자동수정(AutoFixed2): " + c.AutoFixed2 + "건");
  L.push("- 수동 조치(Manual): " + c.Manual + "건 / 검토(Review): " + c.Review + "건");
  L.push("- DOM XSS 고위험(XssHigh): " + c.XssHigh + "건 (jQuery 업그레이드와 별개로 조치 필요)");
  L.push("- 벤더 검토(VendorReview): " + c.VendorReview + "건 (jqGrid/jquery-ui/select2/autoNumeric 등, 직접 수정 금지)");
  L.push("- 정적 HTML 저위험: " + c.StaticHtmlLow + "건 (조치 불필요 후보)");
  L.push("- 사람이 봐야 할 FocusQueue: " + c.FocusQueue + "건");
  L.push("");
  L.push("페이지 리스크");
  L.push("- jQuery core 중복 로드 페이지: " + c.PageRiskMultipleJqueryCore);
  L.push("- 구버전 core 사용 페이지: " + c.PageRiskOldJqueryCore);
  L.push("- Migrate 누락 페이지(" + c.JqueryFloorVersion + "+ 기준): " + c.PageRiskMigrateMissing);
  L.push("- Migrate 선로드 페이지: " + c.PageRiskMigrateBeforeCore);
  L.push("- 미해석 참조: " + c.UnresolvedRefs);
  L.push("");
  L.push("구버전 jQuery 호출부");
  model.oldCoreRefs.forEach(function (r) { L.push("- " + r.page + ":" + r.line + " " + r.raw); });
  L.push("");
  L.push("다음 액션");
  recommendedActions(model).forEach(function (a, i) { L.push((i + 1) + ". " + a); });
  L.push("");
  L.push("XSS 대응용 공통 이스케이프 함수 예시 (필요 시 공통 JS에 추가):");
  L.push("function escapeHtml(v){ return String(v == null ? '' : v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;'); }");
  writeUtf8(path.join(model.reportRoot, "chat_summary.txt"), L.join("\r\n") + "\r\n", true);
}

function writeMockFiles(model) {
  const routes = {};
  model.ajaxRows.forEach(function (r) {
    if (!r.urlNorm || r.urlNorm.indexOf("_EL_") >= 0 || r.urlNorm.indexOf("_JSP_") >= 0) return;
    const key = r.urlNorm;
    if (!routes[key]) routes[key] = { url: key, method: r.method, type: r.mock, hits: 0 };
    routes[key].hits++;
    if (r.mock === "json") routes[key].type = "json";
  });
  const routeArr = Object.keys(routes).sort().map(function (k) { return routes[k]; });
  writeUtf8(path.join(model.reportRoot, "mock_routes.json"), JSON.stringify({ generated: true, routes: routeArr }, null, 2), false);
  const sample = {
    json: { result: "OK", success: true, mock: true, message: "jq35 local lab mock response", rows: [{ col1: "SAMPLE1", col2: "100", col3: "Y" }, { col1: "SAMPLE2", col2: "200", col3: "N" }], totalCount: 2 },
    html: "<div class=\"jq35-mock\">MOCK HTML RESPONSE</div>",
    text: "MOCK TEXT RESPONSE"
  };
  writeUtf8(path.join(model.reportRoot, "mock_data_default.json"), JSON.stringify(sample, null, 2), false);
}

function writeRecommendedCommits(model) {
  const groups = {
    AUTO_SAFE: { title: "safe auto fixes (.on/.off/.prop/.length etc)", files: {} },
    JQUERY_CORE: { title: "jQuery core 1.10.2 -> " + model.profile.jquery.targetVersion + " + Migrate " + model.profile.jquery.migrateVersion, files: {} },
    MANUAL_BOOL_ATTR: { title: "manual boolean attr variable fixes", files: {} },
    DOM_XSS: { title: "html/append/replaceWith DOM XSS candidates", files: {} },
    PROBE_ONLY: { title: "temporary runtime probe for verification (must not reach production)", files: {} },
    VENDOR_REVIEW: { title: "vendor compatibility verification (jqGrid/jquery-ui/select2/autoNumeric)", files: {} }
  };
  model.findings.forEach(function (f) {
    if (groups[f.commitGroup]) groups[f.commitGroup].files[f.rel] = 1;
  });
  const L = ["RECOMMENDED COMMIT GROUPS (" + TOOL_NAME + " v" + TOOL_VERSION + ")", ""];
  let n = 0;
  Object.keys(groups).forEach(function (g) {
    n++;
    const files = Object.keys(groups[g].files).sort();
    L.push(n + ". " + g + " - " + groups[g].title + " (" + files.length + " files)");
    files.slice(0, 200).forEach(function (f) { L.push("   " + f); });
    if (files.length > 200) L.push("   ...(" + (files.length - 200) + " more)");
    L.push("");
  });
  writeUtf8(path.join(model.reportRoot, "recommended_commits.txt"), L.join("\r\n") + "\r\n", true);
}

function writePrReport(model) {
  const c = model.counters;
  const L = [];
  L.push("# jQuery " + CVE_ID + " 보안 조치");
  L.push("");
  L.push("## 목적");
  L.push("- " + CVE_ID + " (jQuery htmlPrefilter XSS) 대응: jQuery core를 " + TARGET_JQUERY_FLOOR_VERSION + " 이상으로 상향");
  L.push("- 적용 조합: jQuery " + model.profile.jquery.targetVersion + " + jQuery Migrate " + model.profile.jquery.migrateVersion);
  L.push("- Migrate는 구버전 API 호환 유지 및 경고 수집 목적 (안정화 후 제거 검토)");
  L.push("");
  L.push("## 변경 요약");
  L.push("| 항목 | 건수 |");
  L.push("|---|---|");
  L.push("| 구버전 jQuery core 호출부(Critical) | " + c.Critical + " |");
  L.push("| 안전 자동수정(AutoFixed) | " + c.AutoFixed + " |");
  L.push("| 콜사이트 추론 자동수정(AutoFixed2) | " + c.AutoFixed2 + " |");
  L.push("| 수동 조치(Manual) | " + c.Manual + " |");
  L.push("| DOM XSS 검토(XssHigh) | " + c.XssHigh + " |");
  L.push("| 벤더 호환성 검토(VendorReview) | " + c.VendorReview + " |");
  L.push("| FocusQueue(잔여 검토 대상) | " + c.FocusQueue + " |");
  L.push("");
  L.push("## 벤더 영향범위");
  const libs = {};
  model.pluginInv.forEach(function (r) { libs[r[1]] = r[5]; });
  Object.keys(libs).forEach(function (k) { L.push("- **" + k + "**: " + libs[k]); });
  L.push("");
  L.push("## 테스트 계획");
  L.push("- [ ] 주요 화면 렌더링/조회/저장 동작");
  L.push("- [ ] jqGrid: 렌더링, 페이징, 정렬, 검색, 인라인 편집, formatter, subgrid");
  L.push("- [ ] jquery-ui: datepicker, dialog, button, tabs, autocomplete");
  L.push("- [ ] select2: placeholder, ajax 검색, 다중 선택, 초기값");
  L.push("- [ ] autoNumeric: 금액 입력, 콤마, blur/focus, 저장값, readonly/disabled");
  L.push("- [ ] Edge IE mode 화면에서 Runtime Probe로 JQMIGRATE warning / JS error 0건 확인");
  L.push("");
  L.push("## 운영 반영 전 체크");
  L.push("- [ ] Runtime Probe script 제거 (verify-clean 모드 FAIL 항목)");
  L.push("- [ ] verify-clean 모드 통과 (구버전 jQuery 잔존 0건)");
  L.push("- [ ] Bamboo branch build 성공");
  L.push("");
  L.push("생성: " + TOOL_NAME + " v" + TOOL_VERSION);
  writeUtf8(path.join(model.reportRoot, "pr_description.md"), L.join("\n") + "\n", true);

  const B = [];
  B.push("# Bamboo / 배포 체크리스트");
  B.push("");
  B.push("- [ ] fix/jquery-cve-2020-11023 브랜치에서 branch build 성공");
  B.push("- [ ] 배포 대상 환경 확인 (개발 -> 검증 -> 운영 순서)");
  B.push("- [ ] 주요 화면 " + Math.min(model.pages.length, 10) + "개 이상 수동 테스트 완료");
  B.push("- [ ] Edge / Edge IE mode 양쪽 확인");
  B.push("- [ ] Runtime Probe 제거 확인 (verify-clean 통과)");
  B.push("- [ ] jquery-1.10.2.min.js 파일 삭제 또는 참조 0건 확인");
  B.push("- [ ] Migrate 콘솔 경고 잔존 여부 기록");
  B.push("- [ ] 롤백 계획: 이전 커밋 revert + 캐시 무효화");
  writeUtf8(path.join(model.reportRoot, "bamboo_checklist.md"), B.join("\n") + "\n", true);
}

function writeRuntimeChecklist(model) {
  const L = [];
  L.push("RUNTIME TEST CHECKLIST (" + TOOL_NAME + " v" + TOOL_VERSION + ")");
  L.push("");
  L.push("[공통]");
  L.push("1. Eclipse/Tomcat 기동 후 아래 페이지 접속");
  L.push("2. 화면 우측 하단 JQ35 배지 클릭 -> 패널에서 E(에러)/M(마이그레이트 경고) 수치 확인");
  L.push("3. Copy 버튼으로 로그 복사 후 기록");
  L.push("");
  L.push("[jQuery core를 로드하는 페이지 목록]");
  model.pages.filter(function (p) { return p.hasCore; }).forEach(function (p) {
    L.push("- " + p.rel + " (core v" + (p.coreVer || "?") + (p.hasMigrate ? ", migrate O" : ", migrate X") + ")");
  });
  L.push("");
  L.push("[체크 항목]");
  L.push("- JQMIGRATE warning 0건 목표 (있으면 apiFindings 대조)");
  L.push("- JS error 0건");
  L.push("- AJAX error 없음");
  L.push("- jqGrid/select2/autoNumeric/datepicker 동작");
  writeUtf8(path.join(model.reportRoot, "runtime_test_checklist.txt"), L.join("\r\n") + "\r\n", true);
}

function writeSampleProfile(model) {
  const p = path.join(model.reportRoot, "project-profile.sample.json");
  writeUtf8(p, JSON.stringify({
    webContentDir: "WebContent",
    pathVariables: DEFAULT_PATH_VARS,
    vendorPatterns: ["resources/jqgrid/", "jquery-ui", "jquery.ui", "select2", "autoNumeric", "jqgrid", "jquery.jqGrid", "grid.locale"],
    appScriptHints: ["js/util.js", "js/common.js"],
    ignoreAttrPatterns: ["aria-"],
    jquery: {
      targetVersion: DEFAULT_JQUERY_VERSION,
      migrateVersion: DEFAULT_MIGRATE_VERSION,
      coreFile: "jquery-" + DEFAULT_JQUERY_VERSION + ".min.js",
      migrateFile: "jquery-migrate-" + DEFAULT_MIGRATE_VERSION + ".min.js",
      newJquerySrc: "",
      newMigrateSrc: "",
      migrateTrace: false
    },
    probe: { enabled: true, injectTargetHints: ["WEB-INF/layouts/common_script_lib.jsp"] },
    learnedWrappers: [],
    learnedFindings: [],
    sensitiveIdentifiers: []
  }, null, 2), false);
}

const REVIEW_PROGRESS_HEADER = ["Round", "TotalAmbiguousGroups", "CasesInPack", "FocusQueue", "Manual", "Review", "XssHigh", "SourceFingerprint"];

function sourceFingerprint(model) {
  let h = 0;
  const s = model.allFiles.map(function (f) { return f.rel + ":" + f.size; }).sort().join("|");
  for (let i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) >>> 0; }
  return h.toString(36).padStart(7, "0");
}

function writeReviewProgress(model) {
  const file = path.join(model.reportRoot, "review_loop_progress.csv");
  const headerLine = REVIEW_PROGRESS_HEADER.map(csvCell).join(",");
  let round = 1;
  let rows = [];
  let targetFile = file;
  let prevFingerprint = "";
  if (exists(file)) {
    try {
      const prevText = readUtf8(file).replace(/^\uFEFF/, "");
      const prevLines = prevText.split(/\r?\n/).filter(Boolean);
      if (prevLines.length > 0 && prevLines[0] === headerLine) {
        rows = prevLines.slice(1);
        round = rows.length + 1;
        if (rows.length > 0) {
          const lastCols = rows[rows.length - 1].split(",");
          prevFingerprint = lastCols[lastCols.length - 1] || "";
        }
      } else if (prevLines.length > 0) {
        const bak = file.replace(/\.csv$/, "") + ".schema-mismatch." + prevLines.length + "rows.bak.csv";
        try {
          fs.renameSync(file, bak);
          warn("review_loop_progress.csv had a different/older column layout; moved old file to " + path.basename(bak) + " and started a fresh round 1");
        } catch (e2) {
          warn("review_loop_progress.csv had a different/older column layout and could not be backed up (" + e2.message + "); writing to review_loop_progress.new.csv instead of overwriting it");
          targetFile = file.replace(/\.csv$/, "") + ".new.csv";
        }
      }
    } catch (e) {
      warn("review_loop_progress.csv could not be read (" + e.message + "); writing to review_loop_progress.new.csv instead of silently discarding round history");
      targetFile = file.replace(/\.csv$/, "") + ".new.csv";
    }
  }
  model.reviewRound = round;
  const fp = sourceFingerprint(model);
  if (round > 1 && prevFingerprint && prevFingerprint !== fp) {
    warn("source tree changed since the previous review-pack round (fingerprint " + prevFingerprint + " -> " + fp + "); caseIds for edited files may no longer line up with earlier learnedFindings answers");
  }
  const row = [round, model.reviewCasesAll, model.reviewCases.length, model.counters.FocusQueue, model.counters.Manual, model.counters.Review, model.counters.XssHigh, fp].map(csvCell).join(",");
  rows.push(row);
  writeUtf8(targetFile, [headerLine].concat(rows).join("\r\n") + "\r\n", true);
}

function writeReviewPack(model) {
  writeReviewProgress(model);
  const R = model.reportRoot;
  ensureDir(R);
  const L = [];
  L.push("JQUERY35_AI_REVIEW_PACK v" + TOOL_VERSION + " r=" + model.reviewRound + " cases=" + model.reviewCases.length + "/" + model.reviewCasesAll);
  L.push("Return JSON only. roles=ajaxSuccessJson|domSinkArg|safeWrapper decisions=xss-high|review|manual|static-safe|vendor-review|ignored");
  L.push("");
  model.reviewCases.forEach(function (g, i) {
    L.push("---- CASE " + (i + 1) + "/" + model.reviewCases.length + " id=" + g.caseId + " ----");
    L.push("k=" + (g.kind === "FN" ? "fn" : "pt") + " name=" + g.name + " fanout=" + (g.fanout || 0) + " occ=" + g.count + " cat=" + g.topCategories.join("|") + " pri=" + g.findings[0].priority + "/" + g.findings[0].confidence);
    L.push("loc=" + g.sampleLocationsShort);
    L.push("code:");
    L.push(g.compactExcerpt);
    L.push("q=" + g.shortQuestion);
    L.push("");
  });
  L.push("ANSWER_JSON=");
  L.push(JSON.stringify({
    learnedWrappers: [
      { caseId: "", name: "", role: "ajaxSuccessJson|domSinkArg|safeWrapper", calleeParamIndex: 1, sinkParamIndex: 0, notes: "" }
    ],
    learnedFindings: [
      { caseId: "", name: "", decision: "xss-high|review|manual|static-safe|vendor-review|ignored", notes: "" }
    ]
  }));
  const capLines = positiveIntOpt(model.opts["max-review-lines"], 300);
  let lines = L;
  if (lines.length > capLines) {
    lines = lines.slice(0, capLines - 1);
    lines.push("...(truncated " + (L.length - capLines + 1) + " lines, adjust with --max-review-lines)");
  }
  writeUtf8(path.join(R, "ai_review_pack.txt"), lines.join("\r\n") + "\r\n", true);

  const jsonOut = {
    tool: TOOL_NAME, version: TOOL_VERSION, round: model.reviewRound,
    totalAmbiguousGroups: model.reviewCasesAll,
    cases: model.reviewCases.map(function (g) {
      return {
        caseId: g.caseId, kind: g.kind, name: g.name,
        fanout: g.fanout, occurrences: g.count,
        sampleLocations: g.sampleLocationsShort,
        categories: g.topCategories,
        currentPriority: g.findings[0].priority,
        currentConfidence: g.findings[0].confidence,
        question: g.shortQuestion,
        excerpt: g.compactExcerpt
      };
    })
  };
  writeUtf8(path.join(R, "ai_review_pack.json"), JSON.stringify(jsonOut) + "\n", false);
  log("review pack: " + model.reviewCases.length + "/" + model.reviewCasesAll + " ambiguous groups (round " + model.reviewRound + ")");
}

function writeAllReports(model, extra) {
  ensureDir(model.reportRoot);
  writeCsvReports(model);
  writeXls(model);
  writeIndexHtml(model);
  writePacket(model);
  writeChatSummary(model);
  writeSampleProfile(model);
  writeRuntimeChecklist(model);
  writeRecommendedCommits(model);
  if (!model.opts["no-lab"]) writeMockFiles(model);
  if (extra && extra.pr) writePrReport(model);
  log("report written: " + model.reportRoot);
  log("  - index.html (dashboard), summary.csv, apiFindings.csv, focusQueue.csv, jquery35_report.xls");
  log("  - assistant_packet.txt / chat_summary.txt (safe to share externally)");
}
const MIME = {
  ".html": "text/html", ".htm": "text/html", ".js": "application/javascript",
  ".css": "text/css", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".gif": "image/gif", ".svg": "image/svg+xml", ".ico": "image/x-icon",
  ".json": "application/json", ".txt": "text/plain", ".woff": "font/woff",
  ".woff2": "font/woff2", ".ttf": "font/ttf", ".map": "application/json", ".xls": "application/vnd.ms-excel", ".csv": "text/csv"
};

function labTransformJsp(model, wcBase, rel, visited, depth) {
  if (depth > 10) return "";
  const abs = path.join(wcBase, rel.split("/").join(path.sep));
  let text;
  try { text = readLatin1(abs); } catch (e) {
    try { text = readLatin1(path.join(model.webContentRoot, rel.split("/").join(path.sep))); } catch (e2) { return ""; }
  }
  text = text.replace(/<%--[\s\S]*?--%>/g, "");
  text = text.replace(/<%@\s*(page|taglib)\b[^%]*%>/gi, "");
  const incRe = /<%@\s*include\s+file\s*=\s*(?:"([^"]*)"|'([^']*)')\s*%>|<jsp:include\s+page\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*\/?>(?:\s*<\/jsp:include>)?/gi;
  text = text.replace(incRe, function (whole, a, b, c, d) {
    const raw = a || b || c || d || "";
    let sub = applyPathVars(raw, model.profile).split(/[?#]/)[0];
    let incRel;
    if (sub.charAt(0) === "/") incRel = normalizeWcPath(sub);
    else incRel = normalizeWcPath(toPosix(path.posix.dirname(toPosix(rel))) + "/" + sub);
    const key = incRel.toLowerCase();
    if (visited[key]) return "";
    visited[key] = true;
    const inner = labTransformJsp(model, wcBase, incRel, visited, depth + 1);
    delete visited[key];
    return inner;
  });
  text = text.replace(/<c:out\b[^>]*value\s*=\s*(?:"\$\{([^}"]*)\}"|'\$\{([^}']*)\}')[^>]*\/?>(?:\s*<\/c:out>)?/gi, function (w, a, b) {
    return "[" + (a || b || "") + "]";
  });
  text = text.replace(/<\/?(c|fmt|spring|tiles|sec|ui|fn|sitemesh):[a-zA-Z]+\b[^>]*>/g, "");
  text = text.replace(/<(\/?)form:([a-zA-Z]+)/g, function (w, close, tag) {
    const map = { form: "form", input: "input", select: "select", option: "option", textarea: "textarea", checkbox: "input", radiobutton: "input", hidden: "input", label: "label", errors: "span", password: "input" };
    return "<" + close + (map[tag.toLowerCase()] || "div");
  });
  text = applyPathVars(text, model.profile);
  text = text.replace(/<%=[\s\S]*?%>/g, "");
  text = text.replace(/<%[\s\S]*?%>/g, "");
  text = text.replace(/\$\{[^{}]*\}/g, "");
  return text;
}

function labPageHtml(model, wcBase, rel) {
  const visited = {};
  visited[rel.toLowerCase()] = true;
  let body = labTransformJsp(model, wcBase, rel, visited, 0);
  const banner = '<div style="position:fixed;top:0;left:0;right:0;z-index:999998;background:#263238;color:#fff;font:12px monospace;padding:4px 10px;">JQ35 LOCAL LAB (mock) - ' + htmlEsc(rel) + ' - JSP/JSTL/DB not executed. Final verification must run on Eclipse/Tomcat. <a href="/_pages" style="color:#8ecbff">[page list]</a></div><div style="height:26px"></div>';
  const probeTag = '<script src="/js/' + PROBE_FILE_NAME + '"></script>';
  if (/<body[^>]*>/i.test(body)) {
    body = body.replace(/(<body[^>]*>)/i, "$1" + banner);
  } else {
    body = banner + body;
  }
  if (/<\/body\s*>/i.test(body)) body = body.replace(/<\/body\s*>/i, probeTag + "</body>");
  else body += probeTag;
  return body;
}

function labPagesListHtml(model) {
  const parts = [];
  parts.push('<!DOCTYPE html><html><head><meta charset="utf-8"><title>JQ35 Lab pages</title><style>body{font-family:monospace;margin:20px;background:#fafafa}h1{font-size:18px}li{margin:2px 0}a{text-decoration:none}.risk{color:#b00020;font-weight:bold}.mig{color:#b26a00}</style></head><body>');
  parts.push("<h1>JQ35 Local Lab - page list (" + model.pages.length + ")</h1>");
  parts.push('<p>mock rendering only: Spring controller / DB / session / tiles are NOT executed.</p><ul>');
  model.pages.slice().sort(function (a, b) { return a.rel < b.rel ? -1 : 1; }).forEach(function (p) {
    let mark = "";
    if (p.oldCore) mark += ' <span class="risk">[old jQuery ' + htmlEsc(p.coreVer) + "]</span>";
    if (p.riskMultiCore) mark += ' <span class="risk">[multi core]</span>';
    if (p.riskMigrateMissing) mark += ' <span class="mig">[migrate missing]</span>';
    parts.push('<li><a href="/_page?p=' + encodeURIComponent(p.rel) + '">' + htmlEsc(p.rel) + "</a>" + mark + "</li>");
  });
  parts.push("</ul></body></html>");
  return parts.join("\n");
}

function startLab(model, opts) {
  const port = parseInt(opts.port, 10) || 18080;
  const wcBase = model.targetWcRoot && isDir(model.targetWcRoot) ? model.targetWcRoot : model.webContentRoot;
  const probeLogDir = path.join(model.reportRoot, "probeLogs");
  const routes = {};
  model.ajaxRows.forEach(function (r) {
    if (r.urlNorm && r.urlNorm.indexOf("_EL_") < 0 && r.urlNorm.indexOf("_JSP_") < 0) {
      routes[r.urlNorm] = { type: r.mock, method: r.method };
    }
  });
  const mock = {
    json: JSON.stringify({ result: "OK", success: true, mock: true, message: "jq35 local lab mock response", rows: [{ col1: "SAMPLE1", col2: "100", col3: "Y" }, { col1: "SAMPLE2", col2: "200", col3: "N" }], totalCount: 2 }),
    html: '<div class="jq35-mock">MOCK HTML RESPONSE</div>'
  };
  const probeJs = genProbeJs();
  const server = http.createServer(function (req, res) {
    try {
      const u = new URL(req.url, "http://localhost");
      const p = decodeURIComponent(u.pathname);
      if (p === "/__probe/log" && req.method === "POST") {
        let body = "";
        req.on("data", function (ch) { if (body.length < 2 * 1024 * 1024) body += ch; });
        req.on("end", function () {
          ensureDir(probeLogDir);
          const fn = path.join(probeLogDir, "probe-" + new Date().toISOString().slice(0, 10) + ".log");
          fs.appendFileSync(fn, "==== " + new Date().toISOString() + " ====\r\n" + body + "\r\n\r\n");
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end('{"ok":true}');
        });
        return;
      }
      if (p === "/" || p === "/_pages") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(labPagesListHtml(model));
        return;
      }
      if (p === "/_page") {
        const rel = normalizeWcPath(u.searchParams.get("p") || "");
        if (!model.ctxByRel[rel] || !model.ctxByRel[rel].isPage) {
          res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
          res.end("unknown page: " + rel + " (see /_pages)");
          return;
        }
        const html = labPageHtml(model, wcBase, rel);
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(Buffer.from(html, "latin1"));
        return;
      }
      if (p.indexOf("/_report/") === 0) {
        const rp = path.join(model.reportRoot, normalizeWcPath(p.slice(9)).split("/").join(path.sep));
        if (isUnderDir(rp, model.reportRoot) && exists(rp) && !isDir(rp)) {
          res.writeHead(200, { "Content-Type": (MIME[path.extname(rp).toLowerCase()] || "application/octet-stream") + "; charset=utf-8" });
          res.end(fs.readFileSync(rp));
          return;
        }
        res.writeHead(404); res.end("not found");
        return;
      }
      if (p === "/js/" + PROBE_FILE_NAME) {
        const onDisk = path.join(wcBase, "js", PROBE_FILE_NAME);
        res.writeHead(200, { "Content-Type": "application/javascript" });
        res.end(exists(onDisk) ? fs.readFileSync(onDisk) : Buffer.from(probeJs, "latin1"));
        return;
      }
      if (p === "/favicon.ico") { res.writeHead(204); res.end(); return; }
      const wcRel = normalizeWcPath(p);
      if (wcRel.toLowerCase().indexOf("web-inf/") === 0) {
        res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("WEB-INF direct access blocked. Use /_page?p=" + wcRel);
        return;
      }
      const fileAbs = path.join(wcBase, wcRel.split("/").join(path.sep));
      if (isUnderDir(fileAbs, wcBase) && exists(fileAbs) && !isDir(fileAbs)) {
        res.writeHead(200, { "Content-Type": MIME[path.extname(fileAbs).toLowerCase()] || "application/octet-stream" });
        res.end(fs.readFileSync(fileAbs));
        return;
      }
      const routeKey = "/" + wcRel;
      const route = routes[routeKey] || routes[wcRel];
      if (route || /\.do$/i.test(wcRel)) {
        const t = route ? route.type : "json";
        if (req.method === "POST" || req.method === "PUT") {
          let b2 = "";
          req.on("data", function (ch) { if (b2.length < 2 * 1024 * 1024) b2 += ch; });
          req.on("end", function () {
            res.writeHead(200, { "Content-Type": t === "json" ? "application/json" : "text/html; charset=utf-8" });
            res.end(t === "json" ? mock.json : mock.html);
          });
          return;
        }
        res.writeHead(200, { "Content-Type": t === "json" ? "application/json" : "text/html; charset=utf-8" });
        res.end(t === "json" ? mock.json : mock.html);
        return;
      }
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("not found: " + p + "\n(hint: pages -> /_pages, reports -> /_report/index.html)");
    } catch (e) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("lab error: " + e.message);
    }
  });
  server.listen(port, "127.0.0.1", function () {
    log("local lab server started (mock, backend NOT executed)");
    log("  pages   : http://localhost:" + port + "/_pages");
    log("  report  : http://localhost:" + port + "/_report/index.html");
    log("  probe rx: POST http://localhost:" + port + "/__probe/log -> " + probeLogDir);
    log("  serving : " + wcBase);
    log("stop with Ctrl+C");
  });
  return server;
}

function doVerifyClean(model, opts) {
  const lines = [];
  let failCount = 0, warnCount = 0;
  const add = function (level, name, detail) {
    lines.push(level + "|" + name + "|" + detail);
    if (level === "FAIL") failCount++;
    if (level === "WARN") warnCount++;
    (level === "FAIL" ? fail : level === "WARN" ? warn : log)(name + ": " + detail);
  };
  if (model.oldCoreRefs.length > 0) {
    add("FAIL", "old-jquery-refs", model.oldCoreRefs.length + " script tag(s) still load jQuery < " + TARGET_JQUERY_FLOOR_VERSION + ": " + model.counters.OldJquerySrcs);
  } else add("PASS", "old-jquery-refs", "no jQuery < " + TARGET_JQUERY_FLOOR_VERSION + " references");
  const multi = model.pages.filter(function (p) { return p.riskMultiCore; });
  if (multi.length > 0) add("FAIL", "multiple-jquery-core", multi.length + " page(s): " + multi.slice(0, 5).map(function (p) { return p.rel; }).join(", "));
  else add("PASS", "multiple-jquery-core", "no page loads jQuery core twice");
  const probeRefs = [];
  model.textFiles.forEach(function (ctx) {
    if (ctx.rel.toLowerCase().indexOf(PROBE_FILE_NAME) >= 0) { probeRefs.push(ctx.rel + " (probe file itself)"); return; }
    if (ctx.text.indexOf(PROBE_FILE_NAME) >= 0 || ctx.text.indexOf(PROBE_MARKER) >= 0) probeRefs.push(ctx.rel);
  });
  model.allFiles.forEach(function (f) {
    if (fileNameOf(f.rel) === PROBE_FILE_NAME && TEXT_EXTS.indexOf(f.ext) < 0) probeRefs.push(f.rel);
  });
  if (probeRefs.length > 0) add("FAIL", "probe-leftover", "runtime probe must be removed before production: " + uniq(probeRefs).slice(0, 10).join(", "));
  else add("PASS", "probe-leftover", "no runtime probe leftovers");
  const crit = model.findings.filter(function (f) { return f.priority === "Critical"; });
  if (crit.length > 0) add("FAIL", "critical-findings", crit.length + " critical finding(s) remain");
  else add("PASS", "critical-findings", "no critical findings");
  const mig = model.pages.filter(function (p) { return p.riskMigrateMissing; });
  if (mig.length > 0) add("WARN", "migrate-missing", mig.length + " page(s) load jQuery " + TARGET_JQUERY_FLOOR_VERSION + "+ without Migrate: " + mig.slice(0, 5).map(function (p) { return p.rel; }).join(", "));
  else add("PASS", "migrate-missing", "all jQuery " + TARGET_JQUERY_FLOOR_VERSION + "+ pages load Migrate");
  const migBefore = model.pages.filter(function (p) { return p.riskMigrateBeforeCore; });
  if (migBefore.length > 0) add("WARN", "migrate-order", migBefore.length + " page(s) load Migrate before jQuery core");
  else add("PASS", "migrate-order", "migrate load order OK");
  const oldFiles = model.scriptInv.filter(function (r) { return String(r[5]).indexOf("OLD_JQUERY_CORE") === 0; });
  if (oldFiles.length > 0) add("WARN", "old-jquery-file-exists", oldFiles.length + " old jQuery file(s) still on disk (unreferenced?): " + oldFiles.map(function (r) { return r[0]; }).join(", "));
  else add("PASS", "old-jquery-file-exists", "no old jQuery core files on disk");
  const synFail = model.syntaxRows.filter(function (r) { return r.result === "FAIL"; });
  if (synFail.length > 0) add("WARN", "js-syntax", synFail.length + " js file(s) failed Node syntax check (may be legacy-IE syntax)");
  else add("PASS", "js-syntax", "all checked js files parse OK");
  add("INFO", "focus-queue-remaining", String(model.focus.length));
  add("INFO", "xss-high-remaining", String(model.counters.XssHigh));
  add("INFO", "vendor-review-remaining", String(model.counters.VendorReview));
  const overall = failCount > 0 ? "FAIL" : warnCount > 0 ? "WARN" : "PASS";
  lines.unshift("RESULT=" + overall);
  lines.unshift("VERIFY_CLEAN " + TOOL_NAME + " v" + TOOL_VERSION + " source=" + model.sourceRoot);
  writeUtf8(path.join(model.reportRoot, "verify_clean_result.txt"), lines.join("\r\n") + "\r\n", true);
  log("verify-clean result: " + overall + " (fail=" + failCount + " warn=" + warnCount + ")");
  let code = 0;
  if (failCount > 0) code = 2;
  else if (warnCount > 0 && opts["warn-as-error"]) code = 1;
  return { code: code, failCount: failCount, warnCount: warnCount, overall: overall };
}

const ST_LAYOUT = [
  '<%@ page contentType="text/html; charset=UTF-8" %>',
  '<script type="text/javascript" src="${js}/jquery-1.10.2.min.js"></script>',
  '<script type="text/javascript" src="${js}/jquery-ui-1.10.4.min.js"></script>',
  '<script type="text/javascript" src="${js}/util.js"></script>'
].join("\r\n");

const ST_LIST_JSP = [
  '<%@ page contentType="text/html; charset=UTF-8" %>',
  '<%@ include file="../../layouts/common_script_lib.jsp" %>',
  "<html><body>",
  '<div id="grid"></div><select id="opt"></select>',
  "<script>",
  "$(document).ready(function(){",
  '  $("#btn1").bind("click", function(){ $("#cnt").text($("#rows").size()); });',
  "  $(window).load(function(){ initPage(); });",
  '  $("#opt").append("<option value=\'\'>ALL</option>");',
  "  $.ajax({ url: \"/sample/list.do\", type: \"POST\", dataType: \"json\",",
  "    success: function(response){ $(\"#grid\").html(response); }",
  "  });",
  '  $("#chk").attr("checked", true);',
  '  $("#inp").removeAttr("readonly");',
  '  $("#inp2").attr("readonly", "true");',
  '  $("#z").append("<div/><span>zz</span>");',
  "});",
  "function initPage(){ }",
  "</script>",
  "</body></html>"
].join("\r\n");

const ST_SECOND_JSP = [
  '<%@ page contentType="text/html; charset=UTF-8" %>',
  "<html><head>",
  '<script src="${pageContext.request.contextPath}/js/jquery-1.10.2.min.js"></script>',
  '<script>var auditCopy = "${pageContext.request.contextPath}/js/jquery-1.10.2.min.js";</script>',
  '<!-- deployment note: ${pageContext.request.contextPath}/js/jquery-1.10.2.min.js -->',
  "</head><body>second page</body></html>"
].join("\r\n");

const ST_UTIL_JS = [
  "function setBtn(sts) {",
  '\t$("#btn").attr("disabled", sts);',
  "}",
  "function toggleAll(flag) {",
  '\t$(".itm").attr("disabled", flag);',
  "}",
  'setBtn("Y");',
  'setBtn("N");',
  "toggleAll(true);",
  "toggleAll(false);",
  'var $list = $("#list");',
  '$list.delegate(".row", "click", onRow);',
  "function onRow() {",
  '\t$list.unbind("mouseover");',
  "}",
  "var fn2 = onRow.bind(this);",
  'var greeting = $.trim(" hi ");',
  "",
  ""
].join("\r\n");

const ST_JQGRID_JS = '(function($){$.fn.fakeGrid=function(o){this.bind("click",function(){});this.attr("disabled",true);return this;};})(jQuery);';

const ST_WRAPPER_JS = [
  "function fnAjaxWrap(url, cb) {",
  '\t$.ajax({ url: url, dataType: "json" }).success(cb);',
  "}",
  "function renderCell(v) {",
  '\t$("#cellHost").html(v);',
  "}",
  "function esc(v) {",
  "\treturn String(v).replace(/[<>&]/g, \"\");",
  "}",
  'fnAjaxWrap("/board/data.do", function(d){',
  '\t$("#out").html(d);',
  "});",
  "renderCell(resultdata);",
  '$("#msgBox").append(esc(response));',
  ""
].join("\r\n");

function selfTest(opts) {
  const base = path.join(os.tmpdir(), "jq35-selftest-" + Date.now());
  const src = path.join(base, "sample-app");
  const wc = path.join(src, "WebContent");
  log("self-test sandbox: " + base);
  writeLatin1(path.join(wc, "WEB-INF", "layouts", "common_script_lib.jsp"), ST_LAYOUT);
  writeLatin1(path.join(wc, "WEB-INF", "views", "sample", "list.jsp"), ST_LIST_JSP);
  writeLatin1(path.join(wc, "WEB-INF", "views", "common", "second_page.jsp"), ST_SECOND_JSP);
  writeLatin1(path.join(wc, "js", "util.js"), ST_UTIL_JS);
  writeLatin1(path.join(wc, "js", "wrapper_demo.js"), ST_WRAPPER_JS);
  writeLatin1(path.join(wc, "js", "jquery-1.10.2.min.js"), "/*! jQuery v1.10.2 | (c) fixture */");
  writeLatin1(path.join(wc, "js", "jquery-ui-1.10.4.min.js"), "/*! jQuery UI 1.10.4 fixture */");
  writeLatin1(path.join(wc, "resources", "jqgrid", "js", "jquery.jqGrid.min.js"), ST_JQGRID_JS);
  writeLatin1(path.join(wc, "css", "common.css"), ".a{color:#000}");
  const results = [];
  const check = function (name, ok, detail) {
    results.push({ name: name, ok: !!ok, detail: detail || "" });
    (ok ? log : fail)("  [" + (ok ? "PASS" : "FAIL") + "] " + name + (detail && !ok ? " -> " + detail : ""));
  };
  const mk = function (extra) {
    return Object.assign({ _: [], "safe-packet": true, "max-packet-lines": "400" }, extra);
  };
  try {
    log("self-test 1/8: plan");
    const t1 = path.join(base, "tobe");
    const r1 = path.join(base, "report");
    const m1 = buildModel(mk({ source: src, target: t1, report: r1 }), "plan");
    analyze(m1);
    writeAllReports(m1, {});
    const c1 = m1.counters;
    check("critical detected (2 old jquery refs)", c1.Critical === 2, "got " + c1.Critical);
    check("autoFixed >= 6", c1.AutoFixed >= 6, "got " + c1.AutoFixed);
    check("autoFixed2 == 2 (sts Y/N + flag bool)", c1.AutoFixed2 === 2, "got " + c1.AutoFixed2);
    check("xssHigh >= 1 (.html(response))", c1.XssHigh >= 1, "got " + c1.XssHigh);
    check("staticHtmlLow >= 1 (append option literal)", c1.StaticHtmlLow >= 1, "got " + c1.StaticHtmlLow);
    check("vendorReview >= 1 (jqgrid fixture)", c1.VendorReview >= 1, "got " + c1.VendorReview);
    check("focusQueue > 0", c1.FocusQueue > 0, "got " + c1.FocusQueue);
    const trimPlanFinding = m1.findings.find(function (f) { return f.rel === "js/util.js" && f.category === "trim-deprecated"; });
    check("trim-deprecated deferred for 3.5.1 landing",
      !!trimPlanFinding && trimPlanFinding.priority === "StaticHtmlLow" && trimPlanFinding.action === "Ignored" && !m1.focus.some(function (f) { return f.category === "trim-deprecated"; }),
      trimPlanFinding ? JSON.stringify([trimPlanFinding.priority, trimPlanFinding.action]) : "finding not found");
    check("effective include resolved (list.jsp sees layout core)", m1.pages.some(function (p) { return p.rel.indexOf("views/sample/list.jsp") >= 0 && p.oldCore && p.effectiveScripts >= 3; }), "");
    check("function-bind not touched (onRow.bind)", !m1.findings.some(function (f) { return f.rel === "js/util.js" && f.category === "bind-to-on" && f.action === "Changed" && f.line >= 16; }), "");
    ["summary.csv", "apiFindings.csv", "focusQueue.csv", "critical.csv", "xssHigh.csv", "assistant_packet.txt", "chat_summary.txt", "index.html", "jquery35_report.xls", "jspPages.csv", "pageScriptEffective.csv", "ajaxEndpoints.csv", "mock_routes.json"].forEach(function (f) {
      check("report file " + f, exists(path.join(r1, f)), "");
    });
    const indexHtml = readUtf8(path.join(r1, "index.html"));
    check("dashboard focus split-view modal present", indexHtml.indexOf("focusDetailModal") >= 0 && indexHtml.indexOf("__JQ35_FOCUS_DETAILS__") >= 0 && indexHtml.indexOf("openFocusDetail(") >= 0, "");
    check("dashboard remediation scope roadmap present", indexHtml.indexOf("조치 범위 로드맵") >= 0 && indexHtml.indexOf("단계별 FocusQueue") >= 0 && indexHtml.indexOf("1차 최소") >= 0 && indexHtml.indexOf("2차 안정화") >= 0 && indexHtml.indexOf("3차 최대/후속") >= 0, "");

    log("self-test 2/8: autofix");
    const m2 = buildModel(mk({ source: src, target: t1, report: r1 }), "autofix");
    analyze(m2);
    writeTarget(m2, {});
    writeAllReports(m2, {});
    const utilTobe = readLatin1(path.join(t1, "WebContent", "js", "util.js"));
    check("AutoFixed2 sts === Y", utilTobe.indexOf('.prop("disabled", sts === "Y")') >= 0, trunc(utilTobe, 200));
    check("AutoFixed2 flag boolean", utilTobe.indexOf('.prop("disabled", flag)') >= 0, "");
    check("delegate -> on", utilTobe.indexOf('.on("click", ".row", onRow)') >= 0, "");
    check("unbind -> off", utilTobe.indexOf('$list.off("mouseover")') >= 0, "");
    check("Function.bind preserved", utilTobe.indexOf("onRow.bind(this)") >= 0, "");
    const listTobe = readLatin1(path.join(t1, "WebContent", "WEB-INF", "views", "sample", "list.jsp"));
    check("window load -> on(load)", listTobe.indexOf('.on("load", function(){ initPage(); })') >= 0, "");
    check("bind -> on in jsp", listTobe.indexOf('$("#btn1").on("click"') >= 0, "");
    check("size -> length", listTobe.indexOf('$("#rows").length') >= 0, "");
    check("attr checked true -> prop", listTobe.indexOf('.prop("checked", true)') >= 0, "");
    check("removeAttr readonly -> prop false", listTobe.indexOf('.prop("readonly", false)') >= 0, "");
    check("attr readonly true-string -> prop true", listTobe.indexOf('.prop("readonly", true)') >= 0, "");
    check(".html(response) NOT auto-changed", listTobe.indexOf('$("#grid").html(response)') >= 0, "");
    check("self-closed tag expanded (jQuery 3.5 htmlPrefilter)", listTobe.indexOf('append("<div></div><span>zz</span>")') >= 0, trunc(listTobe, 300));
    const layoutTobe = readLatin1(path.join(t1, "WebContent", "WEB-INF", "layouts", "common_script_lib.jsp"));
    check("old jquery NOT swapped in autofix", layoutTobe.indexOf("jquery-1.10.2.min.js") >= 0, "");
    const vendorTobe = readLatin1(path.join(t1, "WebContent", "resources", "jqgrid", "js", "jquery.jqGrid.min.js"));
    check("vendor file untouched", vendorTobe === ST_JQGRID_JS, "");

    log("self-test 3/8: probe (separate target)");
    const t2 = path.join(base, "tobe_probe");
    const m3 = buildModel(mk({ source: src, target: t2, report: r1 }), "probe");
    analyze(m3);
    writeTarget(m3, { probe: true });
    check("probe file created", exists(path.join(t2, "WebContent", "js", PROBE_FILE_NAME)), "");
    const layoutProbe = readLatin1(path.join(t2, "WebContent", "WEB-INF", "layouts", "common_script_lib.jsp"));
    check("probe injected into layout", layoutProbe.indexOf(PROBE_FILE_NAME) >= 0, "");

    log("self-test 4/8: verify-clean must FAIL on probe target");
    const rv1 = path.join(base, "report_verify_fail");
    const m4 = buildModel(mk({ source: t2, report: rv1 }), "verify-clean");
    analyze(m4);
    const v1 = doVerifyClean(m4, mk({}));
    check("verify-clean FAIL (old jquery + probe)", v1.code === 2 && v1.failCount >= 2, "code=" + v1.code + " fail=" + v1.failCount);

    log("self-test 5/8: patch-jquery");
    writeLatin1(path.join(wc, "js", "jquery-3.5.1.min.js"), "/*! jQuery v3.5.1 fixture */");
    writeLatin1(path.join(wc, "js", "jquery-migrate-3.6.0.min.js"), "/*! jQuery Migrate v3.6.0 fixture */");
    const t3 = path.join(base, "tobe_patch");
    const m5 = buildModel(mk({ source: src, target: t3, report: r1, "migrate-trace": true }), "patch-jquery");
    analyze(m5);
    writeTarget(m5, { patch: true });
    writeAllReports(m5, {});
    const layoutPatched = readLatin1(path.join(t3, "WebContent", "WEB-INF", "layouts", "common_script_lib.jsp"));
    check("core swapped to 3.5.1", layoutPatched.indexOf("jquery-3.5.1.min.js") >= 0 && layoutPatched.indexOf("jquery-1.10.2.min.js") < 0, trunc(layoutPatched, 200));
    check("migrate inserted after core", layoutPatched.indexOf("jquery-migrate-3.6.0.min.js") >= 0, "");
    check("migrate after core order", layoutPatched.indexOf("jquery-3.5.1.min.js") < layoutPatched.indexOf("jquery-migrate-3.6.0.min.js"), "");
    check("migrate tracing snippet after Migrate",
      layoutPatched.indexOf("jquery-migrate-3.6.0.min.js") < layoutPatched.indexOf("jQuery.migrateTrace = true") &&
      layoutPatched.indexOf("jQuery.migrateMute = false") > layoutPatched.indexOf("jquery-migrate-3.6.0.min.js"),
      trunc(layoutPatched, 300));
    const secondPatched = readLatin1(path.join(t3, "WebContent", "WEB-INF", "views", "common", "second_page.jsp"));
    check("second page swapped too", secondPatched.indexOf("jquery-3.5.1.min.js") >= 0, "");
    check("second migrate inserted", secondPatched.indexOf("jquery-migrate-3.6.0.min.js") >= 0, "");
    check("patch-jquery leaves non-script src text alone",
      secondPatched.indexOf('var auditCopy = "${pageContext.request.contextPath}/js/jquery-1.10.2.min.js"') >= 0 &&
      secondPatched.indexOf('deployment note: ${pageContext.request.contextPath}/js/jquery-1.10.2.min.js') >= 0,
      trunc(secondPatched, 300));

    log("self-test 6/8: verify-clean must PASS on patched target");
    fs.rmSync(path.join(t3, "WebContent", "js", "jquery-1.10.2.min.js"), { force: true });
    const rv2 = path.join(base, "report_verify_pass");
    const m6 = buildModel(mk({ source: t3, report: rv2 }), "verify-clean");
    analyze(m6);
    const v2 = doVerifyClean(m6, mk({}));
    check("verify-clean no FAIL on patched target", v2.failCount === 0, "fail=" + v2.failCount + " overall=" + v2.overall);

    log("self-test 7/8: wrapper learning round-trip (ajaxSuccessJson / domSinkArg / safeWrapper)");
    const rBase = path.join(base, "report_wrapper_baseline");
    const mBase = buildModel(mk({ source: src, report: rBase }), "plan");
    analyze(mBase);
    const wrapBaseFindings = mBase.findings.filter(function (f) { return f.rel === "js/wrapper_demo.js"; });
    check("baseline: .html(d) inside custom wrapper is Review (not yet tainted)",
      wrapBaseFindings.some(function (f) { return f.category === "dom-sink" && f.priority === "Review" && /unknown origin: d\b/.test(f.reason); }),
      JSON.stringify(wrapBaseFindings.map(function (f) { return [f.line, f.category, f.priority, f.reason]; })));
    check("baseline: renderCell(resultdata) produces NO finding (unknown wrapper is invisible)",
      !wrapBaseFindings.some(function (f) { return f.category === "wrapper-dom-sink"; }), "");
    check("baseline: esc(response) is XssHigh (identifier-name false positive)",
      wrapBaseFindings.some(function (f) { return f.category === "dom-sink" && f.priority === "XssHigh" && f.line === 14; }),
      JSON.stringify(wrapBaseFindings.map(function (f) { return [f.line, f.category, f.priority]; })));

    const wrapperProfilePath = path.join(base, "learned-profile.json");
    writeUtf8(wrapperProfilePath, JSON.stringify({
      learnedWrappers: [
        { name: "fnAjaxWrap", role: "ajaxSuccessJson", calleeParamIndex: 1, notes: "custom ajax json wrapper" },
        { name: "renderCell", role: "domSinkArg", sinkParamIndex: 0, notes: "custom cell renderer" },
        { name: "esc", role: "safeWrapper", notes: "html escape helper" }
      ]
    }, null, 2), false);
    const rLearn = path.join(base, "report_wrapper_learned");
    const mLearn = buildModel(mk({ source: src, report: rLearn, profile: wrapperProfilePath }), "plan");
    analyze(mLearn);
    const wrapLearnFindings = mLearn.findings.filter(function (f) { return f.rel === "js/wrapper_demo.js"; });
    check("learned: .html(d) reclassified XssHigh via wrapper taint propagation",
      wrapLearnFindings.some(function (f) { return f.category === "dom-sink" && f.priority === "XssHigh" && /ajax callback parameter 'd'/.test(f.reason); }),
      JSON.stringify(wrapLearnFindings.map(function (f) { return [f.line, f.category, f.priority, f.reason]; })));
    check("learned: renderCell(resultdata) now flagged XssHigh via domSinkArg role",
      wrapLearnFindings.some(function (f) { return f.category === "wrapper-dom-sink" && f.priority === "XssHigh" && f.reason.indexOf("renderCell") >= 0; }),
      JSON.stringify(wrapLearnFindings.map(function (f) { return [f.line, f.category, f.priority]; })));
    check("learned: esc(response) downgraded to StaticHtmlLow via safeWrapper role",
      wrapLearnFindings.some(function (f) { return f.category === "dom-sink" && f.priority === "StaticHtmlLow" && f.line === 14; }),
      JSON.stringify(wrapLearnFindings.map(function (f) { return [f.line, f.category, f.priority]; })));
    check("learned rules never set action=Changed (safety invariant)",
      !wrapLearnFindings.some(function (f) { return (f.category === "dom-sink" || f.category === "wrapper-dom-sink") && f.action === "Changed"; }), "");

    log("self-test 8/8: review-pack round counter + learnedFindings override");
    const rReview = path.join(base, "report_review_pack");
    const mR1 = buildModel(mk({ source: src, report: rReview }), "review-pack");
    analyze(mR1);
    writeAllReports(mR1, {});
    writeReviewPack(mR1);
    check("ai_review_pack.txt created", exists(path.join(rReview, "ai_review_pack.txt")), "");
    check("ai_review_pack.json created", exists(path.join(rReview, "ai_review_pack.json")), "");
    const packTxt = readUtf8(path.join(rReview, "ai_review_pack.txt"));
    check("review pack has marker and at least one CASE", packTxt.indexOf("JQUERY35_AI_REVIEW_PACK") >= 0 && packTxt.indexOf("---- CASE 1/") >= 0, "");
    check("review pack excerpt redacts string literals", !/hi /.test(packTxt) && packTxt.indexOf("<STR:") >= 0, "");
    const packJson = JSON.parse(readUtf8(path.join(rReview, "ai_review_pack.json")));
    check("review pack json cases array non-empty", Array.isArray(packJson.cases) && packJson.cases.length > 0, "");
    check("round counter starts at 1", mR1.reviewRound === 1, "got " + mR1.reviewRound);

    const mR2 = buildModel(mk({ source: src, report: rReview }), "review-pack");
    analyze(mR2);
    writeAllReports(mR2, {});
    writeReviewPack(mR2);
    check("round counter increments on second run in same report dir", mR2.reviewRound === 2, "got " + mR2.reviewRound);

    const learnedCaseId = caseIdOf("FN", "renderCell");
    const overridePath = path.join(base, "learned-findings-profile.json");
    writeUtf8(overridePath, JSON.stringify({
      learnedFindings: [{ caseId: learnedCaseId, decision: "static-safe", notes: "renderCell escapes before this call in the real codebase" }]
    }, null, 2), false);
    const rOverride = path.join(base, "report_override");
    const mOv = buildModel(mk({ source: src, report: rOverride, profile: overridePath }), "plan");
    analyze(mOv);
    const learnedFinding = mOv.findings.find(function (f) { return f.rel === "js/wrapper_demo.js" && f.category === "dom-sink" && f._groupName === "renderCell"; });
    check("learnedFindings override reclassifies renderCell dom-sink to StaticHtmlLow",
      !!learnedFinding && learnedFinding.priority === "StaticHtmlLow" && learnedFinding.action === "Ignored",
      learnedFinding ? JSON.stringify([learnedFinding.priority, learnedFinding.action, learnedFinding.reason]) : "finding not found");
    check("caseIdOf produces distinct wide ids for adjacent numeric names (no truncation collision)",
      caseIdOf("FN", "btn0") !== caseIdOf("FN", "btn1") && caseIdOf("FN", "btn1") !== caseIdOf("FN", "btn2"),
      caseIdOf("FN", "btn0") + " / " + caseIdOf("FN", "btn1") + " / " + caseIdOf("FN", "btn2"));

    const overrideMismatchPath = path.join(base, "learned-findings-mismatch-profile.json");
    writeUtf8(overrideMismatchPath, JSON.stringify({
      learnedFindings: [{ caseId: learnedCaseId, name: "someUnrelatedFunctionName", decision: "static-safe", notes: "corroboration name deliberately wrong" }]
    }, null, 2), false);
    const rMismatch = path.join(base, "report_override_mismatch");
    const mMismatch = buildModel(mk({ source: src, report: rMismatch, profile: overrideMismatchPath }), "plan");
    analyze(mMismatch);
    const learnedFindingMismatch = mMismatch.findings.find(function (f) { return f.rel === "js/wrapper_demo.js" && f.category === "dom-sink" && f._groupName === "renderCell"; });
    check("learnedFindings override skipped when name corroboration mismatches (safety net)",
      !!learnedFindingMismatch && learnedFindingMismatch.priority === "Review" && learnedFindingMismatch.action === "ReviewOnly",
      learnedFindingMismatch ? JSON.stringify([learnedFindingMismatch.priority, learnedFindingMismatch.action]) : "finding not found");
  } catch (e) {
    check("no unexpected exception", false, e.stack || e.message);
  }
  const passN = results.filter(function (r) { return r.ok; }).length;
  const failN = results.length - passN;
  log("");
  log("SELF-TEST RESULT: " + (failN === 0 ? "PASS" : "FAIL") + " (" + passN + "/" + results.length + " checks passed)");
  log("sandbox kept for inspection: " + base);
  return failN === 0 ? 0 : 1;
}

function run(argv) {
  const opts = parseArgs(argv);
  if (opts.help || argv.length === 0) { process.stdout.write(helpText()); return; }
  let mode = opts.mode || "plan";
  if (opts["audit-only"]) mode = "plan";
  if (opts["self-test"]) mode = "self-test";
  if (MODES.indexOf(mode) < 0) {
    fail("unknown mode: " + mode);
    process.stdout.write(helpText());
    process.exitCode = 1;
    return;
  }
  log(TOOL_NAME + " v" + TOOL_VERSION + " mode=" + mode);
  try {
    if (mode === "self-test") {
      process.exitCode = selfTest(opts);
      return;
    }
    if (!opts.report) throw new Error("--report is required");
    const model = buildModel(opts, mode);
    analyze(model);
    if (mode === "plan") {
      writeAllReports(model, {});
    } else if (mode === "autofix" || mode === "patch-jquery" || mode === "probe") {
      writeTarget(model, {
        patch: mode === "patch-jquery" || opts["patch-jquery"] === true,
        probe: mode === "probe" || opts["inject-probe"] === true
      });
      writeAllReports(model, {});
    } else if (mode === "lab") {
      if (!model.opts["no-lab"]) writeMockFiles(model);
      writeIndexHtml(model);
      writePacket(model);
      startLab(model, opts);
      return;
    } else if (mode === "verify-clean") {
      writeAllReports(model, {});
      const v = doVerifyClean(model, opts);
      process.exitCode = v.code;
      return;
    } else if (mode === "pr-report") {
      writeAllReports(model, { pr: true });
    } else if (mode === "packet") {
      ensureDir(model.reportRoot);
      writeCsv(path.join(model.reportRoot, "summary.csv"), ["Key", "Value"], Object.keys(model.counters).map(function (k) { return [k, model.counters[k]]; }));
      writePacket(model);
      writeChatSummary(model);
      log("packet written: " + path.join(model.reportRoot, "assistant_packet.txt"));
    } else if (mode === "review-pack") {
      writeAllReports(model, {});
      writeReviewPack(model);
    }
    const c = model.counters;
    log("");
    log("SUMMARY: files=" + c.TotalFiles + " findings=" + c.ApiFindings +
      " critical=" + c.Critical + " autoFixed=" + (c.AutoFixed + c.AutoFixed2) +
      " manual=" + c.Manual + " xssHigh=" + c.XssHigh + " focusQueue=" + c.FocusQueue);
    if (c.Critical > 0 && mode !== "patch-jquery") {
      warn("old jQuery core references remain (" + c.Critical + "); they are replaced only by patch-jquery mode");
    }
  } catch (e) {
    fail(e.message);
    process.exitCode = 1;
  }
}

module.exports = {
  run: run,
  version: TOOL_VERSION,
  _internal: {
    maskJs: maskJs, receiverInfo: receiverInfo, classifyLib: classifyLib,
    buildModel: buildModel, analyze: analyze, writeTarget: writeTarget,
    doVerifyClean: doVerifyClean, selfTest: selfTest, genProbeJs: genProbeJs
  }
};
