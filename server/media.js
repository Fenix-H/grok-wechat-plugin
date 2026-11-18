import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { assertCdnUrl } from "./safety.js";
import { ensurePrivateHome, homeDir, paths, writePrivateFile } from "./store.js";

const CDN_BASE = "https://novac2c.cdn.weixin.qq.com/c2c";
const MAX_MEDIA_BYTES = 100 * 1024 * 1024;

const IMAGE_BRANDS = new Map([
  ["heic", [".heic", "image/heic", "image"]],
  ["heix", [".heic", "image/heic", "image"]],
  ["hevc", [".heic", "image/heic", "image"]],
  ["hevx", [".heic", "image/heic", "image"]],
  ["heim", [".heic", "image/heic", "image"]],
  ["heis", [".heic", "image/heic", "image"]],
  ["hevm", [".heic", "image/heic", "image"]],
  ["hevs", [".heic", "image/heic", "image"]],
  ["mif1", [".heif", "image/heif", "image"]],
  ["msf1", [".heif", "image/heif", "image"]],
  ["avif", [".avif", "image/avif", "image"]],
  ["avis", [".avif", "image/avif", "image"]],
]);

const VIDEO_BRANDS = new Map([
  ["qt", [".mov", "video/quicktime", "video"]],
  ["mp41", [".mp4", "video/mp4", "video"]],
  ["mp42", [".mp4", "video/mp4", "video"]],
  ["isom", [".mp4", "video/mp4", "video"]],
  ["iso2", [".mp4", "video/mp4", "video"]],
  ["iso4", [".mp4", "video/mp4", "video"]],
  ["iso5", [".mp4", "video/mp4", "video"]],
  ["iso6", [".mp4", "video/mp4", "video"]],
  ["avc1", [".mp4", "video/mp4", "video"]],
  ["dash", [".mp4", "video/mp4", "video"]],
  ["mp4v", [".mp4", "video/mp4", "video"]],
  ["m4v", [".m4v", "video/x-m4v", "video"]],
  ["3gp4", [".3gp", "video/3gpp", "video"]],
  ["3gp5", [".3gp", "video/3gpp", "video"]],
  ["3gp6", [".3gp", "video/3gpp", "video"]],
  ["3g2a", [".3g2", "video/3gpp2", "video"]],
]);

const FILE_MIME = {
  ".pdf": "application/pdf",
  ".txt": "text/plain",
  ".csv": "text/csv",
  ".zip": "application/zip",
  ".gz": "application/gzip",
  ".tgz": "application/gzip",
  ".tar": "application/x-tar",
  ".doc": "application/msword",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xls": "application/vnd.ms-excel",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".ppt": "application/vnd.ms-powerpoint",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ".7z": "application/x-7z-compressed",
};

function decodeBase64Strict(value) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) return null;
  const decoded = Buffer.from(value, "base64");
  if (!decoded.length) return null;
  if (decoded.toString("base64") !== value) return null;
  return decoded;
}

// image_item.aeskey is 32 hex chars. media.aes_key is base64(16 raw bytes)
// or base64(those 32 hex chars). A bare 32-hex string is also accepted.
export function parseAesKey(raw) {
  if (raw == null || raw === "") throw new Error("缺少 aes_key");
  if (typeof raw !== "string") throw new Error("aes_key 类型无效");
  const value = raw.trim();
  if (!value) throw new Error("缺少 aes_key");
  if (/^[0-9a-fA-F]{32}$/.test(value)) return Buffer.from(value, "hex");
  const decoded = decodeBase64Strict(value);
  if (!decoded) throw new Error("aes_key 无法解析为 16 字节密钥");
  if (decoded.length === 16) return decoded;
  const asHex = decoded.toString("ascii");
  if (decoded.length === 32 && /^[0-9a-fA-F]{32}$/.test(asHex)) return Buffer.from(asHex, "hex");
  throw new Error("aes_key 无法解析为 16 字节密钥");
}

export function imageKeyDecision(imageItem) {
  const hex = typeof imageItem?.aeskey === "string" ? imageItem.aeskey.trim() : "";
  const mediaKey = typeof imageItem?.media?.aes_key === "string" ? imageItem.media.aes_key.trim() : "";
  if (hex) {
    if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
      throw new Error("image_item.aeskey 必须是 32 位十六进制");
    }
    return { mode: "decrypt", key: Buffer.from(hex, "hex"), source: "image_item.aeskey" };
  }
  if (mediaKey) return { mode: "decrypt", key: parseAesKey(mediaKey), source: "media.aes_key" };
  return { mode: "plain", source: "plaintext" };
}

export function encryptAesEcb(plaintext, key) {
  if (!Buffer.isBuffer(key) || key.length !== 16) throw new Error("AES 密钥必须是 16 字节");
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

export function decryptAesEcb(ciphertext, key) {
  if (!Buffer.isBuffer(key) || key.length !== 16) throw new Error("AES 密钥必须是 16 字节");
  if (!Buffer.isBuffer(ciphertext) || ciphertext.length === 0) throw new Error("密文为空");
  if (ciphertext.length % 16 !== 0) throw new Error("密文长度不是 16 字节的整数倍");
  try {
    const decipher = crypto.createDecipheriv("aes-128-ecb", key, null);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("媒体解密失败：密钥不匹配或填充无效");
  }
}

export function aesEcbPaddedSize(plaintextSize) {
  return Math.ceil((plaintextSize + 1) / 16) * 16;
}

function brandKey(raw) {
  return raw.replace(/\0/g, " ").trim().toLowerCase();
}

function brandInfo(brand) {
  const hit = IMAGE_BRANDS.get(brand) || VIDEO_BRANDS.get(brand);
  if (!hit) return null;
  return { ext: hit[0], mime: hit[1], kind: hit[2] };
}

function identifyIsoBmff(buf) {
  if (buf.length < 16) return null;
  const size = buf.readUInt32BE(0);
  if (buf.toString("ascii", 4, 8) !== "ftyp") return null;
  if (size !== 0 && (size < 16 || size > buf.length)) return null;
  const end = size === 0 ? buf.length : size;
  const major = brandInfo(brandKey(buf.toString("ascii", 8, 12)));
  if (major) return major;
  for (let offset = 16; offset + 4 <= end; offset += 4) {
    const hit = brandInfo(brandKey(buf.toString("ascii", offset, offset + 4)));
    if (hit) return hit;
  }
  return null;
}

function readVint(buf, pos) {
  if (pos >= buf.length || buf[pos] === 0) return null;
  let width = 1;
  let mask = 0x80;
  while (width <= 8 && (buf[pos] & mask) === 0) {
    width += 1;
    mask >>= 1;
  }
  if (width > 8 || pos + width > buf.length) return null;
  let value = buf[pos] & (mask - 1);
  for (let i = 1; i < width; i += 1) value = value * 256 + buf[pos + i];
  const unknown = 2 ** (7 * width) - 1;
  return { value, next: pos + width, unknown: value === unknown };
}

function readId(buf, pos) {
  if (pos >= buf.length || buf[pos] === 0) return null;
  let width = 1;
  let mask = 0x80;
  while (width <= 4 && (buf[pos] & mask) === 0) {
    width += 1;
    mask >>= 1;
  }
  if ((buf[pos] & mask) === 0 || pos + width > buf.length) return null;
  let id = 0;
  for (let i = 0; i < width; i += 1) id = id * 256 + buf[pos + i];
  return { id, next: pos + width };
}

function ebmlDoctype(buf) {
  if (buf.length < 5 || buf.readUInt32BE(0) !== 0x1a45dfa3) return null;
  const size = readVint(buf, 4);
  if (!size) return null;
  const end = size.unknown ? Math.min(buf.length, size.next + 4096) : Math.min(buf.length, size.next + size.value);
  let pos = size.next;
  while (pos + 2 <= end) {
    const id = readId(buf, pos);
    if (!id || id.next > end) return null;
    const dataSize = readVint(buf, id.next);
    if (!dataSize) return null;
    const dataStart = dataSize.next;
    const dataEnd = dataSize.unknown ? end : dataStart + dataSize.value;
    if (dataEnd > buf.length) return null;
    if (id.id === 0x4282) return buf.toString("ascii", dataStart, dataEnd);
    pos = dataEnd;
  }
  return null;
}

function riffKind(buf) {
  if (buf.length < 12 || buf.toString("ascii", 0, 4) !== "RIFF") return "";
  const size = buf.readUInt32LE(4);
  if (size < 4 || size !== buf.length - 8) return "";
  return buf.toString("ascii", 8, 12);
}

export function identifyMedia(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 3) return null;
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return { ext: ".png", mime: "image/png", kind: "image" };
  }
  if (buf.length >= 20 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { ext: ".jpg", mime: "image/jpeg", kind: "image" };
  }
  const gif = buf.length >= 13 ? buf.toString("ascii", 0, 6) : "";
  if (gif === "GIF87a" || gif === "GIF89a") return { ext: ".gif", mime: "image/gif", kind: "image" };
  const riff = riffKind(buf);
  if (riff === "WEBP") return { ext: ".webp", mime: "image/webp", kind: "image" };
  if (riff === "AVI ") return { ext: ".avi", mime: "video/x-msvideo", kind: "video" };
  if (buf.length >= 26 && buf.toString("ascii", 0, 2) === "BM") {
    const offset = buf.readUInt32LE(10);
    const dib = buf.readUInt32LE(14);
    const knownDib = new Set([12, 40, 52, 56, 64, 108, 124]);
    if (offset >= 14 && offset <= buf.length && knownDib.has(dib)) {
      return { ext: ".bmp", mime: "image/bmp", kind: "image" };
    }
  }
  if (buf.length >= 8) {
    const tiff = buf.toString("ascii", 0, 4);
    if (tiff === "II*\0" || tiff === "MM\0*") return { ext: ".tif", mime: "image/tiff", kind: "image" };
  }
  const doctype = ebmlDoctype(buf);
  if (doctype === "webm") return { ext: ".webm", mime: "video/webm", kind: "video" };
  if (doctype === "matroska") return { ext: ".mkv", mime: "video/x-matroska", kind: "video" };
  if (buf.length >= 4 && buf[0] === 0x46 && buf[1] === 0x4c && buf[2] === 0x56 && buf[3] === 0x01) {
    return { ext: ".flv", mime: "video/x-flv", kind: "video" };
  }
  const iso = identifyIsoBmff(buf);
  if (iso) return iso;
  if (buf.length >= 5 && buf.toString("ascii", 0, 5) === "%PDF-") {
    return { ext: ".pdf", mime: "application/pdf", kind: "file" };
  }
  return null;
}

function declaredSafeFileExt(name) {
  const base = path.basename(String(name || "").replaceAll("\\", "/"));
  const ext = path.extname(base).toLowerCase();
  return Object.prototype.hasOwnProperty.call(FILE_MIME, ext) ? ext : "";
}

function mismatch(role, kind) {
  if (role === "image") return kind !== "image";
  if (role === "video") return kind !== "video";
  return false;
}

function decideExtension(bytes, role, declaredName) {
  const identified = identifyMedia(bytes);
  if (identified) {
    return { ...identified, type_mismatch: mismatch(role, identified.kind) };
  }
  if (role === "image") throw new Error("无法根据文件内容识别图片，已拒绝保存为 .bin 或不可信扩展名");
  if (role === "video") throw new Error("无法根据文件内容识别视频容器，已拒绝保存为 .bin 或不可信扩展名");
  const ext = declaredSafeFileExt(declaredName);
  if (!ext) throw new Error("无法根据文件内容识别媒体，已拒绝沿用不可信扩展名");
  return { ext, mime: FILE_MIME[ext], kind: "file", type_mismatch: false };
}

export function sanitizeDisplayName(name) {
  const base = path.basename(String(name || "").replaceAll("\\", "/")).replace(/[\0\r\n]/g, "");
  if (!base || base === "." || base === "..") return "";
  return base.slice(0, 180);
}

function writeIdentified(bytes, { role, declaredName }) {
  const identified = decideExtension(bytes, role, declaredName);
  ensurePrivateHome();
  const file = path.join(paths().media, `${Date.now()}-${role}-${crypto.randomBytes(4).toString("hex")}${identified.ext}`);
  writePrivateFile(file, bytes);
  const real = fs.realpathSync(file);
  const mediaRoot = fs.realpathSync(paths().media);
  if (real !== mediaRoot && !real.startsWith(`${mediaRoot}${path.sep}`)) {
    fs.unlinkSync(file);
    throw new Error("媒体写入位置异常");
  }
  if (identified.ext === ".bin" || real.endsWith(".bin")) {
    fs.unlinkSync(file);
    throw new Error("已拒绝保存为 .bin");
  }
  return {
    path: real,
    content_type: identified.mime,
    extension: identified.ext,
    detected_kind: identified.kind,
    type_mismatch: Boolean(identified.type_mismatch),
    name: sanitizeDisplayName(declaredName),
  };
}

async function cancelBody(res) {
  try {
    await res?.body?.cancel?.();
  } catch {
    // ignore
  }
}

async function readLimited(res, maxBytes) {
  if (res.body?.getReader) {
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error("媒体超过大小上限");
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBytes) throw new Error("媒体超过大小上限");
  return buf;
}

async function fetchLimited(url, { fetchImpl, timeoutMs, maxBytes }) {
  const fetchFn = fetchImpl || globalThis.fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs ?? 30_000);
  try {
    const res = await fetchFn(url, { method: "GET", redirect: "manual", signal: controller.signal });
    if (res.status >= 300 && res.status < 400) {
      await cancelBody(res);
      throw new Error("媒体下载被重定向，已拒绝跟随");
    }
    if (!res.ok) {
      await cancelBody(res);
      throw new Error(`下载媒体失败 ${res.status}`);
    }
    const declared = Number(res.headers?.get?.("content-length") || 0);
    if (Number.isFinite(declared) && declared > (maxBytes ?? MAX_MEDIA_BYTES)) {
      await cancelBody(res);
      throw new Error("媒体超过大小上限");
    }
    const buf = await readLimited(res, maxBytes ?? MAX_MEDIA_BYTES);
    if (!buf.length) throw new Error("媒体下载内容为空");
    return buf;
  } catch (err) {
    if (err?.name === "AbortError") throw new Error("媒体下载超时");
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function resolveDownloadUrl(media, lookup) {
  const param = typeof media?.encrypt_query_param === "string" ? media.encrypt_query_param.trim() : "";
  const full = typeof media?.full_url === "string" ? media.full_url.trim() : "";
  if (param.length > 4096 || /[\0\r\n]/.test(param)) throw new Error("encrypt_query_param 无效");
  if (full) {
    try {
      return await assertCdnUrl(full, { lookup });
    } catch (err) {
      if (!param) throw err;
    }
  }
  if (param) {
    const built = `${CDN_BASE}/download?encrypted_query_param=${encodeURIComponent(param)}`;
    return assertCdnUrl(built, { lookup });
  }
  throw new Error("图片缺少下载地址");
}

function messageOf(err) {
  return err instanceof Error ? err.message : String(err);
}

export async function ingestItemMedia({
  role,
  media,
  imageItem,
  declaredName,
  fetchImpl,
  lookup,
  maxBytes,
  timeoutMs,
} = {}) {
  try {
    let decision = { source: "" };
    if (role === "image") {
      decision = imageKeyDecision(imageItem || { media });
    } else {
      const rawKey = typeof media?.aes_key === "string" ? media.aes_key.trim() : "";
      if (!rawKey) {
        throw new Error(role === "video"
          ? "视频缺少 media.aes_key，已跳过（缺密钥的视频不按明文处理）"
          : "文件缺少 media.aes_key，已跳过（缺密钥的文件不按明文处理）");
      }
      decision = { mode: "decrypt", key: parseAesKey(rawKey), source: "media.aes_key" };
    }
    const url = await resolveDownloadUrl(media, lookup);
    const downloaded = await fetchLimited(url, { fetchImpl, timeoutMs, maxBytes });
    const plain = decision.mode === "plain" ? downloaded : decryptAesEcb(downloaded, decision.key);
    const saved = writeIdentified(plain, { role, declaredName });
    return { type: role, ...saved, key_source: decision.source };
  } catch (err) {
    const missing = messageOf(err);
    const error = role === "video" && missing === "图片缺少下载地址"
      ? "视频缺少下载地址"
      : role === "file" && missing === "图片缺少下载地址"
        ? "文件缺少下载地址"
        : missing;
    return { type: role, path: null, error };
  }
}

export function interpretQrImage(img) {
  if (typeof img !== "string" || !img.trim()) throw new Error("二维码内容为空");
  const trimmed = img.trim();
  if (/^https:\/\//i.test(trimmed)) {
    let url;
    try {
      url = new URL(trimmed);
    } catch {
      throw new Error("二维码链接无效");
    }
    if (url.username || url.password || url.protocol !== "https:") throw new Error("二维码链接必须是 https");
    return { kind: "url", url: url.toString() };
  }
  if (/^http:\/\//i.test(trimmed)) throw new Error("二维码链接必须是 https");
  let b64 = trimmed;
  const data = trimmed.match(/^data:(image\/[a-z0-9.+-]+);base64,([a-z0-9+/=\s]+)$/i);
  if (data) b64 = data[2].replace(/\s+/g, "");
  else if (/^[a-z0-9+/=\s]+$/i.test(trimmed) && trimmed.replace(/\s+/g, "").length >= 32) b64 = trimmed.replace(/\s+/g, "");
  else throw new Error("无法识别二维码图片或链接");
  const buf = decodeBase64Strict(b64);
  if (!buf) throw new Error("二维码图片不是有效的 base64");
  const identified = identifyMedia(buf);
  if (!identified || identified.kind !== "image") throw new Error("二维码内容不是可识别的图片");
  return { kind: "image", buffer: buf, content_type: identified.mime, extension: identified.ext };
}

function assertInsideHome(file, homeReal) {
  const parent = path.dirname(file);
  if (!fs.existsSync(parent)) throw new Error("二维码目录不存在");
  const parentReal = fs.realpathSync(parent);
  if (parentReal !== homeReal && !parentReal.startsWith(`${homeReal}${path.sep}`)) {
    throw new Error("二维码只能写入 GROK_WECHAT_HOME");
  }
}

export function saveQrArtifact(interpreted, dest) {
  ensurePrivateHome();
  const home = fs.realpathSync(homeDir());
  const requested = dest
    ? path.resolve(dest)
    : path.join(home, interpreted.kind === "url" ? "login-qr.url" : `login-qr${interpreted.extension || ".png"}`);
  assertInsideHome(requested, home);
  const base = path.basename(requested).toLowerCase();
  if (["account.json", "wake.json", "inbox.jsonl", "monitor.log", "monitor.pid", "mcp-host.log"].includes(base)) {
    throw new Error("拒绝覆盖状态文件");
  }
  if (interpreted.kind === "url") {
    const ext = path.extname(requested);
    const file = `${ext ? requested.slice(0, -ext.length) : requested}.url`;
    assertInsideHome(file, home);
    writePrivateFile(file, `${interpreted.url}\n`);
    return { kind: "url", path: file, url: interpreted.url };
  }
  const currentExt = path.extname(requested).toLowerCase();
  const file = currentExt === interpreted.extension
    ? requested
    : `${currentExt ? requested.slice(0, -currentExt.length) : requested}${interpreted.extension}`;
  assertInsideHome(file, home);
  writePrivateFile(file, interpreted.buffer);
  return { kind: "image", path: file, content_type: interpreted.content_type, extension: interpreted.extension };
}
