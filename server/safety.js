import { timingSafeEqual } from "node:crypto";
import { promises as dns } from "node:dns";
import fs from "node:fs";
import net, { BlockList } from "node:net";
import path from "node:path";
import { ensurePrivateHome, fallbackWakePath, homeDir, paths } from "./store.js";

const MAX_MEDIA_BYTES = 100 * 1024 * 1024;

const SECRET_KEYS = new Set([
  "token",
  "bot_token",
  "aes_key",
  "aeskey",
  "authorization",
  "context_token",
  "wake_key",
  "key",
]);

let forbiddenIps;

function forbiddenList() {
  if (forbiddenIps) return forbiddenIps;
  const list = new BlockList();
  const v4 = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ];
  for (const [addr, prefix] of v4) list.addSubnet(addr, prefix, "ipv4");
  list.addSubnet("::", 128, "ipv6");
  list.addSubnet("::1", 128, "ipv6");
  list.addSubnet("fc00::", 7, "ipv6");
  list.addSubnet("fe80::", 10, "ipv6");
  list.addSubnet("ff00::", 8, "ipv6");
  list.addSubnet("2001:db8::", 32, "ipv6");
  forbiddenIps = list;
  return list;
}

function ipv4From6to4(ip) {
  const match = /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?::|$)/i.exec(ip);
  if (!match) return "";
  const hi = Number.parseInt(match[1], 16);
  const lo = Number.parseInt(match[2], 16);
  if (!Number.isFinite(hi) || !Number.isFinite(lo)) return "";
  return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
}

export function isForbiddenIpAddress(ip) {
  if (typeof ip !== "string" || !ip.trim()) return true;
  let current = ip.trim().toLowerCase();
  if (current.startsWith("::ffff:")) {
    const mapped = current.slice(7);
    if (net.isIP(mapped) === 4) current = mapped;
  }
  const embedded = ipv4From6to4(current);
  if (embedded) return isForbiddenIpAddress(embedded);
  const family = net.isIP(current);
  if (!family) return true;
  return forbiddenList().check(current, family === 6 ? "ipv6" : "ipv4");
}

export function redactSensitive(text) {
  return String(text ?? "")
    .replace(/("(?:token|bot_token|aes_key|aeskey|authorization|context_token|wake_key|key)"\s*:\s*")[^"]*(")/gi, "$1[redacted]$2")
    .replace(/(Bearer\s+)\S+/gi, "$1[redacted]");
}

export function assertPublicJson(value) {
  const walk = (node) => {
    if (Array.isArray(node)) {
      for (const entry of node) walk(entry);
      return;
    }
    if (!node || typeof node !== "object") return;
    for (const [key, entry] of Object.entries(node)) {
      if (SECRET_KEYS.has(key.toLowerCase())) throw new Error("输出包含不应展示的字段");
      walk(entry);
    }
  };
  walk(value);
  return value;
}

function isBlockedHostname(host) {
  const name = host.toLowerCase().replace(/\.$/, "");
  if (!name || !name.includes(".")) return true;
  if (net.isIP(name)) return true;
  if (/^\d+$/.test(name)) return true;
  const blocked = new Set(["localhost", "localhost.localdomain", "metadata.google.internal", "metadata.google.com"]);
  if (blocked.has(name)) return true;
  if (name.endsWith(".localhost") || name.endsWith(".local") || name.endsWith(".internal")) return true;
  return false;
}

export function canonicalizeHttpsUrl(raw) {
  if (typeof raw !== "string" || !raw.trim()) throw new Error("webhook 地址为空");
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error("webhook 地址无效");
  }
  if (url.protocol !== "https:") throw new Error("webhook 只接受 https");
  if (url.username || url.password) throw new Error("webhook 地址不能包含用户信息");
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (isBlockedHostname(host)) throw new Error("webhook 主机无效");
  url.hostname = host;
  url.hash = "";
  if (url.port === "443") url.port = "";
  return url.toString();
}

export function readWakeEnv() {
  const urlRaw = process.env.GROK_WECHAT_WAKE_URL?.trim() ?? "";
  const key = process.env.GROK_WECHAT_WAKE_KEY?.trim() ?? "";
  if (!urlRaw && !key) return null;
  if (!urlRaw || !key) throw new Error("GROK_WECHAT_WAKE_URL 与 GROK_WECHAT_WAKE_KEY 必须同时设置");
  if (key.length > 4096) throw new Error("webhook 密钥无效");
  return { url: canonicalizeHttpsUrl(urlRaw), key };
}

function timingSafeEqualString(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) {
    timingSafeEqual(left, left);
    return false;
  }
  return timingSafeEqual(left, right);
}

export function assertWakeArgsMatchEnv(url, key) {
  const env = readWakeEnv();
  if (!env) {
    throw new Error("未设置 GROK_WECHAT_WAKE_URL 与 GROK_WECHAT_WAKE_KEY，已拒绝保存调用方提供的 webhook");
  }
  const urlProvided = typeof url === "string" && url.trim() !== "";
  const keyProvided = typeof key === "string" && key.trim() !== "";
  if (urlProvided) {
    let canonical;
    try {
      canonical = canonicalizeHttpsUrl(url);
    } catch {
      throw new Error("webhook 参数与环境变量不一致");
    }
    if (canonical !== env.url) throw new Error("webhook 参数与环境变量不一致");
  }
  if (keyProvided && !timingSafeEqualString(key.trim(), env.key)) {
    throw new Error("webhook 参数与环境变量不一致");
  }
  return env;
}

async function defaultLookup(hostname) {
  return dns.lookup(hostname, { all: true, verbatim: true });
}

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function assertResolvedPublic(host, lookup, noun) {
  const fn = lookup || defaultLookup;
  let records;
  try {
    records = await withTimeout(Promise.resolve(fn(host)), 5_000, `${noun}主机解析超时，已拒绝`);
  } catch (err) {
    if (err instanceof Error && err.message.includes("解析超时")) throw err;
    throw new Error(`${noun}主机解析失败，已拒绝`);
  }
  const list = Array.isArray(records) ? records : [records];
  if (!list.length) throw new Error(`${noun}主机解析失败，已拒绝`);
  for (const record of list) {
    const address = typeof record === "string" ? record : record?.address;
    if (!address || isForbiddenIpAddress(address)) {
      throw new Error(`${noun}主机不是公网地址，已拒绝`);
    }
  }
}

function hostMatchesSuffix(host, suffix) {
  return host === suffix || host.endsWith(`.${suffix}`);
}

function cdnSuffixes() {
  const suffixes = ["cdn.weixin.qq.com"];
  const extra = process.env.GROK_WECHAT_CDN_HOST_SUFFIXES || "";
  for (const part of extra.split(",")) {
    const suffix = part.trim().toLowerCase().replace(/^\*\./, "").replace(/^\./, "").replace(/\.$/, "");
    if (!suffix) continue;
    if (suffix !== "weixin.qq.com" && !suffix.endsWith(".weixin.qq.com")) {
      throw new Error("GROK_WECHAT_CDN_HOST_SUFFIXES 只能是 weixin.qq.com 域名");
    }
    suffixes.push(suffix);
  }
  return suffixes;
}

export async function assertCdnUrl(raw, { lookup } = {}) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("媒体下载地址无效");
  }
  if (url.protocol !== "https:") throw new Error("媒体下载地址必须是 https");
  if (url.username || url.password) throw new Error("媒体下载地址无效");
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (isBlockedHostname(host) || !cdnSuffixes().some((suffix) => hostMatchesSuffix(host, suffix))) {
    throw new Error("媒体下载地址不在微信 CDN 允许列表");
  }
  await assertResolvedPublic(host, lookup, "媒体下载");
  return url.toString();
}

async function cancelBody(res) {
  try {
    await res?.body?.cancel?.();
  } catch {
    // ignore
  }
}

async function wakeRequest(env, { fetchImpl, lookup, timeoutMs, withAuth, body }) {
  await assertResolvedPublic(new URL(env.url).hostname, lookup, "webhook ");
  const fetchFn = fetchImpl || globalThis.fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs ?? 10_000);
  const headers = { "Content-Type": "application/json" };
  if (withAuth) headers.Authorization = `Bearer ${env.key}`;
  try {
    const res = await fetchFn(env.url, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers,
      body: JSON.stringify(body),
    });
    await cancelBody(res);
    if (res.status >= 300 && res.status < 400) {
      throw new Error("webhook 返回重定向，已拒绝跟随");
    }
    return { status: res.status };
  } catch (err) {
    if (err?.name === "AbortError") throw new Error("webhook 请求超时");
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export async function probeWebhook(options = {}) {
  const env = readWakeEnv();
  if (!env) throw new Error("未配置 webhook 环境变量，已拒绝发送");
  return wakeRequest(env, {
    ...options,
    withAuth: false,
    body: { source: "grok-wechat", probe: true, count: 0 },
  });
}

export async function postWebhook(body, options = {}) {
  const env = readWakeEnv();
  if (!env) throw new Error("未配置 webhook 环境变量，已拒绝发送");
  return wakeRequest(env, { ...options, withAuth: true, body });
}

function sensitiveBasename(base) {
  const lower = base.toLowerCase();
  const names = new Set([
    "account.json",
    "wake.json",
    "inbox.jsonl",
    "monitor.log",
    "monitor.pid",
    "mcp-host.log",
    ".env",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials.json",
    "secrets.json",
    "shadow",
    "passwd",
    "sudoers",
    "authorized_keys",
    "known_hosts",
  ]);
  if (names.has(lower) || lower.startsWith(".env") || lower.startsWith("login-qr")) return true;
  return /\.(pem|key|p12|pfx|kdbx)$/.test(lower);
}

function assertNotBroad(real) {
  const segments = real.split(path.sep).filter(Boolean);
  if (segments.length < 2) throw new Error("GROK_WECHAT_SEND_ROOTS 过宽，请指定具体目录");
  const banned = new Set(["tmp", "proc", "sys", "dev", "etc", "run", "private", "var"]);
  if (banned.has(segments[0]) && segments.length < 3) {
    throw new Error("GROK_WECHAT_SEND_ROOTS 不能指向系统目录");
  }
  const denied = ["/proc", "/sys", "/dev", "/etc", "/run"];
  if (denied.some((prefix) => real === prefix || real.startsWith(`${prefix}${path.sep}`))) {
    throw new Error("GROK_WECHAT_SEND_ROOTS 不能指向系统目录");
  }
}

export function listSendRoots() {
  ensurePrivateHome();
  const mediaRoot = fs.realpathSync(paths().media);
  const home = fs.realpathSync(homeDir());
  const roots = [mediaRoot];
  const extra = process.env.GROK_WECHAT_SEND_ROOTS;
  if (!extra) return roots;
  for (const part of extra.split(path.delimiter)) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    if (!path.isAbsolute(trimmed)) throw new Error("GROK_WECHAT_SEND_ROOTS 必须是绝对路径");
    let real;
    try {
      real = fs.realpathSync(trimmed);
    } catch {
      throw new Error("GROK_WECHAT_SEND_ROOTS 目录不存在");
    }
    if (!fs.statSync(real).isDirectory()) throw new Error("GROK_WECHAT_SEND_ROOTS 必须是目录");
    assertNotBroad(real);
    if (real === home || real.startsWith(`${home}${path.sep}`) || home.startsWith(`${real}${path.sep}`)) {
      throw new Error("GROK_WECHAT_SEND_ROOTS 不能包含状态目录");
    }
    if (!roots.includes(real)) roots.push(real);
  }
  return roots;
}

function sameInodeAsSecrets(stat) {
  const files = [paths().state, fallbackWakePath(), paths().inbox, paths().log, paths().pid, path.join(homeDir(), "mcp-host.log")];
  for (const file of files) {
    try {
      const other = fs.statSync(file);
      if (other.dev === stat.dev && other.ino === stat.ino) return true;
    } catch {
      // missing secret file
    }
  }
  return false;
}

function deniesSensitive(real, stat) {
  if (sameInodeAsSecrets(stat) || sensitiveBasename(path.basename(real))) return true;
  const mediaRoot = fs.realpathSync(paths().media);
  if (real === mediaRoot || real.startsWith(`${mediaRoot}${path.sep}`)) return false;
  const dirs = new Set([".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config", ".npm"]);
  if (real.split(path.sep).some((part) => dirs.has(part))) return true;
  const home = fs.realpathSync(homeDir());
  if (real === home || real.startsWith(`${home}${path.sep}`)) return true;
  const denied = ["/proc", "/sys", "/dev", "/etc", "/run"];
  return denied.some((prefix) => real === prefix || real.startsWith(`${prefix}/`));
}

function isInside(child, root) {
  return child === root || child.startsWith(`${root}${path.sep}`);
}

export function readSendableMedia(filePath) {
  if (typeof filePath !== "string" || !filePath.trim() || filePath.includes("\0")) {
    throw new Error("缺少媒体路径");
  }
  ensurePrivateHome();
  const resolved = path.resolve(filePath);
  let real;
  try {
    real = fs.realpathSync(resolved);
  } catch {
    throw new Error("文件不存在");
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let fd;
  try {
    fd = fs.openSync(real, flags);
  } catch {
    throw new Error("拒绝读取该媒体路径");
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new Error("媒体路径必须是普通文件");
    if (stat.size <= 0) throw new Error("媒体文件为空");
    if (stat.size > MAX_MEDIA_BYTES) throw new Error("媒体超过大小上限");
    if (deniesSensitive(real, stat)) throw new Error("拒绝读取凭据或状态文件");
    const roots = listSendRoots();
    if (!roots.some((root) => isInside(real, root))) throw new Error("拒绝读取允许目录之外的文件");
    const buf = Buffer.alloc(stat.size);
    fs.readSync(fd, buf, 0, stat.size, 0);
    return { path: real, bytes: buf };
  } finally {
    fs.closeSync(fd);
  }
}
