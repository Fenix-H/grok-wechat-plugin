import { execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_BASE = "https://ilinkai.weixin.qq.com";
const MAX_LOCAL_TOKENS = 10;

export function homeDir() {
  const raw = process.env.GROK_WECHAT_HOME?.trim();
  if (raw) return path.resolve(raw);
  return path.join(os.homedir(), ".grok-wechat");
}

export function paths() {
  const home = homeDir();
  return {
    home,
    state: path.join(home, "account.json"),
    inbox: path.join(home, "inbox.jsonl"),
    pid: path.join(home, "monitor.pid"),
    media: path.join(home, "media"),
    log: path.join(home, "monitor.log"),
  };
}

export function emptyAccount() {
  return {
    token: "",
    baseUrl: DEFAULT_BASE,
    ilinkBotId: "",
    ilinkUserId: "",
    getUpdatesBuf: "",
    contextTokens: {},
    typingTickets: {},
    wake: null,
    dedicatedAssistant: null,
  };
}

export function emptyState() {
  return {
    accounts: [],
    pendingQrs: [],
    allowFrom: [],
  };
}

function chmodOwnerOnly(target, mode) {
  fs.chmodSync(target, mode);
  const got = fs.statSync(target).mode & 0o777;
  if (got !== mode) {
    throw new Error(`权限设置失败：需要 ${mode.toString(8)}，实际 ${got.toString(8)}`);
  }
}

function ensureDir(dir, mode) {
  if (fs.existsSync(dir) && fs.lstatSync(dir).isSymbolicLink()) {
    throw new Error(`拒绝使用符号链接目录: ${path.basename(dir)}`);
  }
  fs.mkdirSync(dir, { recursive: true, mode });
  if (fs.lstatSync(dir).isSymbolicLink()) {
    throw new Error(`拒绝使用符号链接目录: ${path.basename(dir)}`);
  }
  chmodOwnerOnly(dir, mode);
}

function ensureHome() {
  const { home, media, state, inbox, log, pid } = paths();
  ensureDir(home, 0o700);
  ensureDir(media, 0o700);
  for (const file of [state, inbox, log, pid, fallbackWakePath(), path.join(home, "mcp-host.log")]) {
    if (!fs.existsSync(file)) continue;
    if (fs.lstatSync(file).isSymbolicLink()) throw new Error("拒绝使用符号链接状态文件");
    chmodOwnerOnly(file, 0o600);
  }
}

export function ensurePrivateHome() {
  ensureHome();
  return homeDir();
}

export function writePrivateFile(file, data) {
  ensureHome();
  if (fs.existsSync(file) && fs.lstatSync(file).isSymbolicLink()) {
    throw new Error(`拒绝写入符号链接: ${path.basename(file)}`);
  }
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = fs.openSync(tmp, "w", 0o600);
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  chmodOwnerOnly(tmp, 0o600);
  fs.renameSync(tmp, file);
  chmodOwnerOnly(file, 0o600);
}

function migrateLegacyState(raw) {
  if (Array.isArray(raw.accounts)) return raw;
  const state = emptyState();
  if (raw.token) {
    state.accounts.push({
      ...emptyAccount(),
      token: raw.token,
      baseUrl: raw.baseUrl || DEFAULT_BASE,
      ilinkBotId: raw.ilinkBotId || "",
      ilinkUserId: raw.ilinkUserId || "",
      getUpdatesBuf: raw.getUpdatesBuf || "",
      contextTokens: raw.contextTokens || {},
      typingTickets: raw.typingTickets || {},
    });
  }
  if (raw.pendingQr?.qrcode) {
    state.pendingQrs.push(raw.pendingQr);
  }
  state.allowFrom = raw.allowFrom || [];
  return state;
}

function redactWakeFile() {
  const wakeFile = fallbackWakePath();
  if (!fs.existsSync(wakeFile)) return;
  if (fs.lstatSync(wakeFile).isSymbolicLink()) throw new Error("拒绝使用符号链接状态文件");
  let cfg;
  try {
    cfg = JSON.parse(fs.readFileSync(wakeFile, "utf8"));
  } catch {
    chmodOwnerOnly(wakeFile, 0o600);
    return;
  }
  if (cfg && Object.prototype.hasOwnProperty.call(cfg, "key")) {
    const url = typeof cfg.url === "string" ? cfg.url : "";
    writePrivateFile(wakeFile, JSON.stringify(url ? { url } : {}, null, 2));
    return;
  }
  chmodOwnerOnly(wakeFile, 0o600);
}

export function loadState() {
  ensureHome();
  const { state } = paths();
  if (!fs.existsSync(state)) {
    redactWakeFile();
    return emptyState();
  }
  if (fs.lstatSync(state).isSymbolicLink()) throw new Error("拒绝使用符号链接状态文件");
  chmodOwnerOnly(state, 0o600);
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(state, "utf8"));
  } catch {
    redactWakeFile();
    return emptyState();
  }
  const next = { ...emptyState(), ...migrateLegacyState(parsed) };
  let changed = false;
  for (const account of next.accounts || []) {
    if (account?.wake && Object.prototype.hasOwnProperty.call(account.wake, "key")) {
      const url = typeof account.wake.url === "string" ? account.wake.url : "";
      account.wake = url ? { url } : null;
      changed = true;
    }
  }
  if (changed) saveState(next);
  redactWakeFile();
  return next;
}

export function saveState(next) {
  ensureHome();
  const { state } = paths();
  if (fs.existsSync(state) && fs.lstatSync(state).isSymbolicLink()) {
    throw new Error("拒绝使用符号链接状态文件");
  }
  writePrivateFile(state, JSON.stringify(next, null, 2));
}

export function updateState(mutator) {
  const current = loadState();
  const next = mutator(current) ?? current;
  saveState(next);
  return next;
}

export function listAccounts(state = loadState()) {
  return state.accounts.filter((a) => a.token);
}

export function findAccount(state, { ilink_bot_id, ilink_user_id, token } = {}) {
  if (ilink_bot_id) {
    const hit = state.accounts.find((a) => a.ilinkBotId === ilink_bot_id);
    if (hit) return hit;
  }
  if (ilink_user_id) {
    const hit = state.accounts.find((a) => a.ilinkUserId === ilink_user_id);
    if (hit) return hit;
  }
  if (token) {
    const hit = state.accounts.find((a) => a.token === token);
    if (hit) return hit;
  }
  return null;
}

export function requireAccount(state, { ilink_bot_id, ilink_user_id } = {}) {
  if (ilink_bot_id || ilink_user_id) {
    const account = findAccount(state, { ilink_bot_id, ilink_user_id });
    if (!account?.token) {
      throw new Error(`未找到账号 ilink_bot_id=${ilink_bot_id || ""} ilink_user_id=${ilink_user_id || ""}`);
    }
    return account;
  }
  const accounts = listAccounts(state);
  if (!accounts.length) throw new Error("未登录。先 wechat_login_start 出码，立即 wechat_login_wait 至 logged_in=true");
  if (accounts.length === 1) return accounts[0];
  throw new Error("已绑定多个微信账号，请指定 ilink_bot_id");
}

export function localTokenList(state = loadState()) {
  return listAccounts(state)
    .map((a) => a.token)
    .slice(0, MAX_LOCAL_TOKENS);
}

export function upsertAccount(state, account) {
  const idx = state.accounts.findIndex((a) =>
  (account.ilinkBotId && a.ilinkBotId === account.ilinkBotId)
  || (account.token && a.token === account.token));
  if (idx >= 0) {
    state.accounts[idx] = { ...state.accounts[idx], ...account };
    const [updated] = state.accounts.splice(idx, 1);
    state.accounts.unshift(updated);
  } else {
    state.accounts.unshift(account);
  }
  return state;
}

export function removeAccount(state, { ilink_bot_id, ilink_user_id } = {}) {
  state.accounts = state.accounts.filter((a) => {
    if (ilink_bot_id && a.ilinkBotId === ilink_bot_id) return false;
    if (ilink_user_id && a.ilinkUserId === ilink_user_id) return false;
    return true;
  });
  return state;
}

export function rememberContext(state, account, userId, contextToken) {
  if (!account || !userId || !contextToken) return state;
  account.contextTokens[userId] = { token: contextToken, at: Date.now() };
  return state;
}

export function contextFor(account, userId) {
  const entry = account?.contextTokens?.[userId];
  return entry?.token || "";
}

export function accountsWithContext(state, userId) {
  return listAccounts(state).filter((a) => contextFor(a, userId));
}

export function resolveAccountForPeer(state, { to_user_id, ilink_bot_id } = {}) {
  if (ilink_bot_id) return requireAccount(state, { ilink_bot_id });
  if (!to_user_id) throw new Error("没有目标用户。传入 to_user_id，或等对方先发一条微信");
  const matches = accountsWithContext(state, to_user_id);
  if (!matches.length) {
    throw new Error("还没有该用户的 context_token。对方需要先从微信给你发一条消息，会话通道才会建立");
  }
  if (matches.length > 1) {
    throw new Error(`多个账号都能回复 ${to_user_id}，请指定 ilink_bot_id`);
  }
  return matches[0];
}

export function isAllowed(state, userId) {
  if (!userId) return false;
  if (!state.allowFrom?.length) return true;
  return state.allowFrom.includes(userId);
}

export function appendInbox(messages) {
  if (!messages.length) return;
  ensureHome();
  const { inbox } = paths();
  const lines = messages.map((m) => JSON.stringify(m)).join("\n") + "\n";
  if (!fs.existsSync(inbox)) writePrivateFile(inbox, lines);
  else {
    if (fs.lstatSync(inbox).isSymbolicLink()) throw new Error("拒绝使用符号链接状态文件");
    fs.appendFileSync(inbox, lines);
    chmodOwnerOnly(inbox, 0o600);
  }
}

export function drainInbox() {
  const { inbox } = paths();
  if (!fs.existsSync(inbox)) return [];
  const raw = fs.readFileSync(inbox, "utf8");
  fs.writeFileSync(inbox, "");
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

export function peekInboxCount() {
  const { inbox } = paths();
  if (!fs.existsSync(inbox)) return 0;
  return fs
    .readFileSync(inbox, "utf8")
    .split("\n")
    .filter((line) => line.trim()).length;
}

export function writePid(pid) {
  ensureHome();
  writePrivateFile(paths().pid, String(pid));
}

export function appendPrivateLog(name, line) {
  const base = path.basename(name);
  if (base !== name || !/^[\w.-]+$/.test(base)) throw new Error("日志名无效");
  ensureHome();
  const file = path.join(homeDir(), base);
  if (fs.existsSync(file) && fs.lstatSync(file).isSymbolicLink()) {
    throw new Error("拒绝使用符号链接状态文件");
  }
  fs.appendFileSync(file, line, { mode: 0o600 });
  chmodOwnerOnly(file, 0o600);
}

export function readPid() {
  const { pid } = paths();
  if (!fs.existsSync(pid)) return 0;
  const n = Number(fs.readFileSync(pid, "utf8").trim());
  return Number.isInteger(n) && n > 0 ? n : 0;
}

export function clearPid() {
  const { pid } = paths();
  if (fs.existsSync(pid)) fs.unlinkSync(pid);
}

export function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function monitorEntryPath() {
  return fileURLToPath(new URL("./index.js", import.meta.url));
}

function sameFile(token, entry) {
  if (token === entry) return true;
  if (!token || token.startsWith("-") || !token.includes(path.sep)) return false;
  try {
    return fs.realpathSync(token) === fs.realpathSync(entry);
  } catch {
    return false;
  }
}

function containsArg(line, token) {
  let from = 0;
  while (from <= line.length) {
    const idx = line.indexOf(token, from);
    if (idx < 0) return false;
    const before = idx === 0 ? " " : line[idx - 1];
    const after = line[idx + token.length] ?? " ";
    if (/\s/.test(before) && /\s/.test(after)) return true;
    from = idx + Math.max(token.length, 1);
  }
  return false;
}

function readLinuxArgv(pid) {
  try {
    const parts = fs.readFileSync(`/proc/${pid}/cmdline`).toString("utf8").split("\0").filter(Boolean);
    return parts.length ? parts : null;
  } catch {
    return null;
  }
}

function readPosixCommand(pid) {
  try {
    const comm = execFileSync("ps", ["-p", String(pid), "-o", "comm="], {
      encoding: "utf8",
      timeout: 2000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    const args = execFileSync("ps", ["-ww", "-p", String(pid), "-o", "args="], {
      encoding: "utf8",
      timeout: 2000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (!comm || !args) return null;
    return { comm, args };
  } catch {
    return null;
  }
}

function commandLineIsMonitor(line, entry) {
  if (!containsArg(line, "--monitor")) return false;
  if (containsArg(line, entry)) return true;
  try {
    const real = fs.realpathSync(entry);
    return real !== entry && containsArg(line, real);
  } catch {
    return false;
  }
}

// Linux thread ids share the pid namespace, so kill(pid, 0) can succeed for a
// live thread inside the MCP host. A recorded id counts only when argv is this
// install's server entry plus --monitor.
export function isMonitorProcess(pid) {
  if (!isPidAlive(pid)) return false;
  const entry = monitorEntryPath();
  if (process.platform === "linux") {
    const argv = readLinuxArgv(pid);
    return Boolean(argv && argv.includes("--monitor") && argv.some((arg) => sameFile(arg, entry)));
  }
  const info = readPosixCommand(pid);
  if (!info || path.basename(info.comm) !== path.basename(process.execPath)) return false;
  return commandLineIsMonitor(info.args, entry);
}

export function monitorRunning() {
  const pid = readPid();
  if (!pid) return 0;
  if (isMonitorProcess(pid)) return pid;
  clearPid();
  return 0;
}

export function stopMonitorProcess() {
  const pid = monitorRunning();
  if (!pid || !isMonitorProcess(pid)) {
    if (pid) clearPid();
    return 0;
  }
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    // already gone
  }
  clearPid();
  return pid;
}

export function fallbackWakePath() {
  return path.join(homeDir(), "wake.json");
}

export function isWakeEnvStaticallyValid() {
  const urlRaw = process.env.GROK_WECHAT_WAKE_URL?.trim();
  const key = process.env.GROK_WECHAT_WAKE_KEY?.trim();
  if (!urlRaw || !key) return false;
  try {
    const url = new URL(urlRaw);
    if (url.protocol !== "https:" || url.username || url.password) return false;
    const host = url.hostname.toLowerCase();
    if (!host.includes(".") || net.isIP(host) || host.endsWith(".internal") || host.endsWith(".local")) return false;
    return true;
  } catch {
    return false;
  }
}

export function loadFallbackWake() {
  const wakeFile = fallbackWakePath();
  if (!fs.existsSync(wakeFile)) return null;
  try {
    const cfg = JSON.parse(fs.readFileSync(wakeFile, "utf8"));
    if (typeof cfg.url === "string" && cfg.url) return { url: cfg.url };
  } catch {
    // ignore
  }
  return null;
}

export function saveGlobalWake(url) {
  ensureHome();
  const wakeFile = fallbackWakePath();
  if (fs.existsSync(wakeFile) && fs.lstatSync(wakeFile).isSymbolicLink()) {
    throw new Error("拒绝使用符号链接状态文件");
  }
  writePrivateFile(wakeFile, JSON.stringify({ url }, null, 2));
}

export function hasGlobalWake() {
  return isWakeEnvStaticallyValid();
}

export function resolveWakeForAccount() {
  if (!isWakeEnvStaticallyValid()) return null;
  try {
    return { url: new URL(process.env.GROK_WECHAT_WAKE_URL.trim()).toString() };
  } catch {
    return null;
  }
}

export function hasAccountWake() {
  return isWakeEnvStaticallyValid();
}

export function saveStateSecure(next) {
  saveState(next);
  chmodOwnerOnly(paths().state, 0o600);
}
