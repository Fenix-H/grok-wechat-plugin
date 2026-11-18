import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import { collectInbound, normalizeInbound, sendText, setAccountWake, statusPayload } from "./ilink.js";
import {
  decryptAesEcb,
  encryptAesEcb,
  identifyMedia,
  imageKeyDecision,
  ingestItemMedia,
  interpretQrImage,
  parseAesKey,
  saveQrArtifact,
} from "./media.js";
import {
  isForbiddenIpAddress,
  listSendRoots,
  postWebhook,
  probeWebhook,
  readSendableMedia,
  readWakeEnv,
  redactSensitive,
} from "./safety.js";
import { hasGlobalWake, loadState, paths, saveState, writePrivateFile } from "./store.js";
import { presentLogin, presentQr, presentSend } from "./text-cli.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixtures = path.join(root, "server", "fixtures");
const KEY_HEX = "00112233445566778899aabbccddeeff";
const KEY = Buffer.from(KEY_HEX, "hex");
const OTHER = Buffer.from("ffeeddccbbaa99887766554433221100", "hex");

function fixture(name) {
  return fs.readFileSync(path.join(fixtures, name));
}

function publicLookup() {
  return [{ address: "1.1.1.1", family: 4 }];
}

function privateLookup() {
  return [{ address: "10.0.0.1", family: 4 }];
}

async function withTempHome(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "grok-wechat-"));
  const prev = {
    GROK_WECHAT_HOME: process.env.GROK_WECHAT_HOME,
    GROK_WECHAT_WAKE_URL: process.env.GROK_WECHAT_WAKE_URL,
    GROK_WECHAT_WAKE_KEY: process.env.GROK_WECHAT_WAKE_KEY,
    GROK_WECHAT_SEND_ROOTS: process.env.GROK_WECHAT_SEND_ROOTS,
    GROK_WECHAT_CDN_HOST_SUFFIXES: process.env.GROK_WECHAT_CDN_HOST_SUFFIXES,
  };
  process.env.GROK_WECHAT_HOME = dir;
  delete process.env.GROK_WECHAT_WAKE_URL;
  delete process.env.GROK_WECHAT_WAKE_KEY;
  delete process.env.GROK_WECHAT_SEND_ROOTS;
  delete process.env.GROK_WECHAT_CDN_HOST_SUFFIXES;
  try {
    await fn(dir);
  } finally {
    for (const [key, value] of Object.entries(prev)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function response(status, body) {
  const buf = Buffer.from(body);
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => null },
    body: null,
    arrayBuffer: async () => buf,
  };
}

test("parseAesKey accepts 32-hex, base64 raw, and base64 hex forms", () => {
  const b64Raw = KEY.toString("base64");
  const b64Hex = Buffer.from(KEY_HEX, "utf8").toString("base64");
  assert.deepEqual(parseAesKey(KEY_HEX), KEY);
  assert.deepEqual(parseAesKey(KEY_HEX.toUpperCase()), KEY);
  assert.deepEqual(parseAesKey(b64Raw), KEY);
  assert.deepEqual(parseAesKey(b64Hex), KEY);
  assert.equal(imageKeyDecision({ aeskey: KEY_HEX, media: { aes_key: OTHER.toString("base64") } }).source, "image_item.aeskey");
  assert.equal(imageKeyDecision({ aeskey: "  ", media: { aes_key: b64Hex } }).source, "media.aes_key");
  assert.equal(imageKeyDecision({ media: {} }).source, "plaintext");
});

test("malformed aes keys and ciphertext fail with clear errors", () => {
  for (const bad of ["", "   ", "abcd", "gggggggggggggggggggggggggggggggg", "@@@@", null, 1, {}]) {
    assert.throws(() => parseAesKey(bad), /aes_key|缺少/);
  }
  assert.throws(() => parseAesKey(Buffer.alloc(15).toString("base64")), /16 字节/);
  assert.throws(() => parseAesKey(Buffer.from("z".repeat(32)).toString("base64")), /16 字节/);
  assert.throws(() => imageKeyDecision({ aeskey: KEY.toString("base64") }), /32 位十六进制/);
  const cipher = crypto.createCipheriv("aes-128-ecb", KEY, null);
  cipher.setAutoPadding(false);
  const bogus = Buffer.concat([cipher.update(Buffer.alloc(16, 0)), cipher.final()]);
  assert.throws(() => decryptAesEcb(bogus, KEY), /媒体解密失败/);
  assert.throws(() => decryptAesEcb(Buffer.alloc(15, 1), KEY), /整数倍/);
  assert.throws(() => decryptAesEcb(Buffer.alloc(0), KEY), /密文为空/);
  assert.deepEqual(decryptAesEcb(encryptAesEcb(Buffer.from("hello"), KEY), KEY), Buffer.from("hello"));
});

test("forbidden addresses cover loopback, private, link-local, and mapped forms", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "2002:0a00:0001::"]) {
    assert.equal(isForbiddenIpAddress(ip), true, ip);
  }
  for (const ip of ["1.1.1.1", "8.8.8.8", "172.32.0.1", "::ffff:1.1.1.1", "2606:4700:4700::1111"]) {
    assert.equal(isForbiddenIpAddress(ip), false, ip);
  }
});

test("text inbound does not download media", async () => {
  await withTempHome(async () => {
    const original = globalThis.fetch;
    let called = 0;
    globalThis.fetch = () => {
      called += 1;
      throw new Error("network");
    };
    try {
      const msg = await normalizeInbound({
        from_user_id: "peer",
        context_token: "ctx-canary",
        item_list: [{ type: 1, text_item: { text: "hello" } }],
      });
      assert.equal(msg.text, "hello");
      assert.equal(msg.items[0].type, "text");
      assert.equal(called, 0);
    } finally {
      globalThis.fetch = original;
    }
  });
});

test("image keys, plaintext fallback, and container extensions", async () => {
  await withTempHome(async () => {
    const png = fixture("sample.png");
    const jpg = fixture("sample.jpg");
    const mp4 = fixture("sample.mp4");
    const webm = fixture("sample.webm");
    const mov = fixture("sample.mov");
    assert.equal(identifyMedia(png).ext, ".png");
    assert.equal(identifyMedia(jpg).ext, ".jpg");
    assert.equal(identifyMedia(fixture("sample.gif")).ext, ".gif");
    assert.equal(identifyMedia(fixture("sample.webp")).ext, ".webp");
    assert.equal(identifyMedia(mp4).ext, ".mp4");
    assert.equal(identifyMedia(webm).ext, ".webm");
    assert.equal(identifyMedia(mov).ext, ".mov");
    assert.equal(identifyMedia(Buffer.from("not-a-container")), null);

    const calls = [];
    const fetchImpl = async (url) => {
      calls.push(url);
      return response(200, encryptAesEcb(png, KEY));
    };
    const preferred = await ingestItemMedia({
      role: "image",
      imageItem: { aeskey: KEY_HEX, media: { aes_key: OTHER.toString("base64"), encrypt_query_param: "abc" } },
      media: { aes_key: OTHER.toString("base64"), encrypt_query_param: "abc" },
      fetchImpl,
      lookup: publicLookup,
    });
    assert.equal(preferred.key_source, "image_item.aeskey");
    assert.equal(preferred.extension, ".png");
    assert.equal(preferred.path.endsWith(".bin"), false);
    assert.deepEqual(fs.readFileSync(preferred.path), png);
    assert.equal(fs.statSync(preferred.path).mode & 0o777, 0o600);
    assert.match(calls[0], /^https:\/\/novac2c\.cdn\.weixin\.qq\.com\/c2c\/download\?/);

    calls.length = 0;
    const plain = await ingestItemMedia({
      role: "image",
      imageItem: { media: { full_url: "http://169.254.169.254/latest/meta-data", encrypt_query_param: "plain" } },
      media: { full_url: "http://169.254.169.254/latest/meta-data", encrypt_query_param: "plain" },
      fetchImpl: async (url) => {
        calls.push(url);
        return response(200, png);
      },
      lookup: publicLookup,
    });
    assert.equal(plain.key_source, "plaintext");
    assert.equal(plain.extension, ".png");
    assert.match(calls[0], /^https:\/\/novac2c\.cdn\.weixin\.qq\.com\//);
    assert.equal(calls.some((url) => url.includes("169.254.169.254")), false);

    const bad = await ingestItemMedia({
      role: "image",
      imageItem: { aeskey: "not-a-key", media: { aes_key: KEY.toString("base64"), encrypt_query_param: "x" } },
      media: { aes_key: KEY.toString("base64"), encrypt_query_param: "x" },
      fetchImpl: () => { throw new Error("should-not-fetch"); },
      lookup: publicLookup,
    });
    assert.equal(bad.path, null);
    assert.match(bad.error, /32 位十六进制/);

    const video = await ingestItemMedia({
      role: "video",
      media: { aes_key: Buffer.from(KEY_HEX, "utf8").toString("base64"), encrypt_query_param: "vid" },
      declaredName: "clip.bin",
      fetchImpl: async () => response(200, encryptAesEcb(mp4, KEY)),
      lookup: publicLookup,
    });
    assert.equal(video.extension, ".mp4");
    assert.equal(video.detected_kind, "video");
    assert.deepEqual(fs.readFileSync(video.path), mp4);

    const webmSaved = await ingestItemMedia({
      role: "video",
      media: { aes_key: KEY.toString("base64"), full_url: "https://novac2c.cdn.weixin.qq.com/c2c/download?x=1" },
      fetchImpl: async (url) => {
        assert.match(url, /^https:\/\/novac2c\.cdn\.weixin\.qq\.com\//);
        return response(200, encryptAesEcb(webm, KEY));
      },
      lookup: publicLookup,
    });
    assert.equal(webmSaved.extension, ".webm");

    const movSaved = await ingestItemMedia({
      role: "image",
      imageItem: { media: { encrypt_query_param: "mov" } },
      media: { encrypt_query_param: "mov" },
      fetchImpl: async () => response(200, mov),
      lookup: publicLookup,
    });
    assert.equal(movSaved.extension, ".mov");
    assert.equal(movSaved.type_mismatch, true);
    assert.equal(movSaved.detected_kind, "video");

    const unknown = await ingestItemMedia({
      role: "video",
      media: { aes_key: KEY_HEX, encrypt_query_param: "bad" },
      fetchImpl: async () => response(200, encryptAesEcb(Buffer.alloc(64, 7), KEY)),
      lookup: publicLookup,
    });
    assert.equal(unknown.path, null);
    assert.match(unknown.error, /无法根据文件内容识别视频容器/);
    assert.equal(fs.readdirSync(paths().media).some((name) => name.endsWith(".bin")), false);

    const missing = await ingestItemMedia({
      role: "video",
      media: { encrypt_query_param: "vid" },
      fetchImpl: () => { throw new Error("should-not-fetch"); },
      lookup: publicLookup,
    });
    assert.match(missing.error, /视频缺少 media.aes_key/);

    const rebind = await ingestItemMedia({
      role: "image",
      imageItem: { media: { full_url: "https://novac2c.cdn.weixin.qq.com/c2c/download?x=1" } },
      media: { full_url: "https://novac2c.cdn.weixin.qq.com/c2c/download?x=1" },
      fetchImpl: () => { throw new Error("should-not-fetch"); },
      lookup: privateLookup,
    });
    assert.match(rebind.error, /不是公网地址/);

    const redirect = await ingestItemMedia({
      role: "image",
      imageItem: { media: { encrypt_query_param: "r" } },
      media: { encrypt_query_param: "r" },
      fetchImpl: async () => response(302, png),
      lookup: publicLookup,
    });
    assert.match(redirect.error, /重定向/);

    const escaped = await ingestItemMedia({
      role: "file",
      media: { aes_key: KEY_HEX, encrypt_query_param: "f" },
      declaredName: "../../account.json",
      fetchImpl: async () => response(200, encryptAesEcb(png, KEY)),
      lookup: publicLookup,
    });
    assert.equal(escaped.extension, ".png");
    assert.equal(fs.realpathSync(escaped.path).startsWith(fs.realpathSync(paths().media) + path.sep), true);
  });
});

test("credential files stay private and webhook keys are not stored or probed", async () => {
  await withTempHome(async () => {
    const previous = process.umask(0);
    try {
      saveState({ accounts: [], pendingQrs: [], allowFrom: [] });
      assert.equal(fs.statSync(paths().state).mode & 0o777, 0o600);
      assert.equal(fs.statSync(paths().home).mode & 0o777, 0o700);
      assert.equal(fs.statSync(paths().media).mode & 0o777, 0o700);
    } finally {
      process.umask(previous);
    }

    const canary = "wake-key-canary";
    fs.writeFileSync(paths().state, JSON.stringify({
      accounts: [{
        token: "token-canary",
        baseUrl: "https://ilinkai.weixin.qq.com",
        ilinkBotId: "bot-1",
        ilinkUserId: "user-1",
        contextTokens: {},
        typingTickets: {},
        wake: { url: "https://evil.example/hook", key: canary },
      }],
      pendingQrs: [],
      allowFrom: [],
    }, null, 2));
    fs.writeFileSync(path.join(paths().home, "wake.json"), JSON.stringify({ url: "https://evil.example/hook", key: canary }));
    const loaded = loadState();
    const raw = fs.readFileSync(paths().state, "utf8") + fs.readFileSync(path.join(paths().home, "wake.json"), "utf8");
    assert.equal(raw.includes(canary), false);
    assert.equal(loaded.accounts[0].token, "token-canary");
    assert.equal(loaded.accounts[0].wake.key, undefined);
    assert.equal(fs.statSync(paths().state).mode & 0o777, 0o600);
    assert.equal(hasGlobalWake(), false);

    process.env.GROK_WECHAT_WAKE_URL = "https://hooks.example/wake";
    process.env.GROK_WECHAT_WAKE_KEY = canary;
    assert.equal(hasGlobalWake(), true);
    const calls = [];
    const saved = await setAccountWake("", "https://hooks.example/wake", canary, {
      lookup: publicLookup,
      fetchImpl: async (url, init) => {
        calls.push({ url, init });
        return response(204, "");
      },
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].init.headers.Authorization, undefined);
    assert.equal(JSON.stringify(calls[0].init).includes(canary), false);
    assert.equal(JSON.stringify(saved).includes(canary), false);
    const wakeRaw = fs.readFileSync(path.join(paths().home, "wake.json"), "utf8");
    assert.equal(wakeRaw.includes(canary), false);
    assert.match(wakeRaw, /hooks\.example/);
    assert.equal(fs.statSync(path.join(paths().home, "wake.json")).mode & 0o777, 0o600);

    await assert.rejects(
      () => setAccountWake("", "https://evil.example/steal", canary, {
        lookup: publicLookup,
        fetchImpl: () => { throw new Error("should-not-fetch"); },
      }),
      /不一致/,
    );
    delete process.env.GROK_WECHAT_WAKE_URL;
    process.env.GROK_WECHAT_WAKE_URL = "http://hooks.example/wake";
    assert.throws(() => readWakeEnv(), /https/);
    process.env.GROK_WECHAT_WAKE_URL = "https://127.0.0.1/hook";
    assert.throws(() => readWakeEnv(), /主机无效/);
    process.env.GROK_WECHAT_WAKE_URL = "https://metadata.google.internal/hook";
    assert.throws(() => readWakeEnv(), /主机无效/);
    process.env.GROK_WECHAT_WAKE_URL = "https://hooks.example/wake";
    await assert.rejects(
      () => probeWebhook({ lookup: privateLookup, fetchImpl: () => { throw new Error("should-not-fetch"); } }),
      /公网/,
    );
    const posted = [];
    await assert.rejects(
      () => postWebhook({ source: "grok-wechat", count: 1 }, {
        lookup: publicLookup,
        fetchImpl: async (url, init) => {
          posted.push({ url, init });
          return response(302, "");
        },
      }),
      /重定向/,
    );
    assert.equal(posted.length, 1);
    assert.equal(posted[0].init.redirect, "manual");
    assert.match(posted[0].init.headers.Authorization, /^Bearer /);
    assert.equal(posted[0].url, "https://hooks.example/wake");
    assert.equal(JSON.stringify(posted[0].init.body).includes(canary), false);
  });
});

test("outbound media reads stay inside allowed roots", async () => {
  await withTempHome(async () => {
    const jpg = fixture("sample.jpg");
    writePrivateFile(path.join(paths().media, "ok.jpg"), jpg);
    const read = readSendableMedia(path.join(paths().media, "ok.jpg"));
    assert.deepEqual(read.bytes, jpg);

    saveState({
      accounts: [{ token: "token-canary", baseUrl: "https://ilinkai.weixin.qq.com", ilinkBotId: "b", ilinkUserId: "u", contextTokens: {}, typingTickets: {} }],
      pendingQrs: [],
      allowFrom: [],
    });
    assert.throws(() => readSendableMedia(paths().state), /凭据或状态文件|允许目录之外/);
    assert.throws(() => readSendableMedia(path.join(paths().home, "..", path.basename(paths().home), "account.json")), /凭据或状态文件|允许目录之外/);
    fs.linkSync(paths().state, path.join(paths().media, "photo.jpg"));
    assert.throws(() => readSendableMedia(path.join(paths().media, "photo.jpg")), /凭据或状态文件/);
    const outside = path.join(os.tmpdir(), `outside-${process.pid}.jpg`);
    fs.writeFileSync(outside, jpg);
    try {
      assert.throws(() => readSendableMedia(outside), /允许目录之外/);
      process.env.GROK_WECHAT_SEND_ROOTS = "/";
      assert.throws(() => listSendRoots(), /过宽|系统目录|状态目录/);
    } finally {
      fs.rmSync(outside, { force: true });
      delete process.env.GROK_WECHAT_SEND_ROOTS;
    }
    const sendRoot = path.join(os.tmpdir(), "gw-nest", `${process.pid}`, "out");
    fs.mkdirSync(sendRoot, { recursive: true });
    const sendFile = path.join(sendRoot, "pic.jpg");
    fs.writeFileSync(sendFile, jpg);
    try {
      process.env.GROK_WECHAT_SEND_ROOTS = sendRoot;
      assert.deepEqual(readSendableMedia(sendFile).bytes, jpg);
      fs.writeFileSync(path.join(sendRoot, ".env"), "SECRET=1");
      assert.throws(() => readSendableMedia(path.join(sendRoot, ".env")), /凭据或状态文件/);
    } finally {
      delete process.env.GROK_WECHAT_SEND_ROOTS;
      fs.rmSync(path.join(os.tmpdir(), "gw-nest"), { recursive: true, force: true });
    }
  });
});

test("QR and text presenters omit bot token and context token", async () => {
  await withTempHome(async () => {
    const png = fixture("sample.png");
    const interpreted = interpretQrImage(`data:image/png;base64,${png.toString("base64")}`);
    const saved = saveQrArtifact(interpreted, path.join(paths().home, "login-qr.png"));
    assert.equal(saved.extension, ".png");
    assert.equal(fs.statSync(saved.path).mode & 0o777, 0o600);
    const shown = presentQr({ qrcode: "qr-123", bot_token: "BOTTOKEN-CANARY", token: "BOTTOKEN-CANARY" }, saved);
    assert.equal(JSON.stringify(shown).includes("BOTTOKEN-CANARY"), false);
    assert.equal(shown.path, saved.path);
    assert.throws(() => interpretQrImage("http://ilinkai.weixin.qq.com/qr"), /https/);
    assert.equal(interpretQrImage("https://weixin.qq.com/qr").kind, "url");
    assert.throws(() => saveQrArtifact(interpreted, path.join(os.tmpdir(), "qr.png")), /GROK_WECHAT_HOME/);
    assert.throws(() => saveQrArtifact(interpreted, paths().state), /拒绝覆盖/);

    const login = presentLogin({ logged_in: true, bot_token: "BOTTOKEN-CANARY", ilink_bot_id: "bot", ilink_user_id: "user", account: { token: "BOTTOKEN-CANARY" } });
    assert.equal(JSON.stringify(login).includes("BOTTOKEN-CANARY"), false);
    assert.equal(login.ilink_bot_id, "bot");
    const sent = presentSend({ to_user_id: "peer", context_token: "ctx-canary", ret: 0, ilink_bot_id: "bot" });
    assert.equal(JSON.stringify(sent).includes("ctx-canary"), false);
    assert.match(redactSensitive('{"bot_token":"BOTTOKEN-CANARY"} Authorization: Bearer BOTTOKEN-CANARY'), /\[redacted\]/);
    assert.equal(redactSensitive('{"bot_token":"BOTTOKEN-CANARY"}').includes("BOTTOKEN-CANARY"), false);
  });
});

test("drain-inbox CLI prints no webhook key", async () => {
  await withTempHome(async (dir) => {
    const result = spawnSync(process.execPath, ["server/index.js", "--drain-inbox"], {
      cwd: root,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        GROK_WECHAT_HOME: dir,
        GROK_WECHAT_WAKE_URL: "https://hooks.example/wake",
        GROK_WECHAT_WAKE_KEY: "wake-key-canary",
      },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(`${result.stdout}${result.stderr}`.includes("wake-key-canary"), false);
    assert.deepEqual(JSON.parse(result.stdout), { messages: [] });
  });
});

test("existing QR account.json keeps its token field and status does not reveal it", async () => {
  await withTempHome(async () => {
    const fixtureToken = "fixture-token-not-real";
    const original = {
      accounts: [{
        token: fixtureToken,
        baseUrl: "https://ilinkai.weixin.qq.com",
        ilinkBotId: "bot-qr",
        ilinkUserId: "user-qr",
        getUpdatesBuf: "",
        contextTokens: { "peer-1": { token: "ctx-1", at: 1 } },
        typingTickets: {},
        wake: null,
        dedicatedAssistant: null,
      }],
      pendingQrs: [],
      allowFrom: [],
    };
    fs.writeFileSync(paths().state, JSON.stringify(original, null, 2));
    const loaded = loadState();
    assert.equal(loaded.accounts[0].token, fixtureToken);
    assert.equal(loaded.accounts[0].ilinkBotId, "bot-qr");
    assert.equal(loaded.accounts[0].contextTokens["peer-1"].token, "ctx-1");
    const status = statusPayload();
    assert.equal(status.logged_in, true);
    assert.equal(status.accounts[0].ilink_bot_id, "bot-qr");
    assert.equal(JSON.stringify(status).includes(fixtureToken), false);
    saveState(loadState());
    const again = JSON.parse(fs.readFileSync(paths().state, "utf8"));
    assert.equal(again.accounts[0].token, fixtureToken);
    assert.equal(fs.statSync(paths().state).mode & 0o777, 0o600);

    const collected = await collectInbound([{
      message_type: 1,
      message_state: 2,
      from_user_id: "peer-1",
      context_token: "ctx-2",
      item_list: [{ type: 1, text_item: { text: "ping" } }],
    }], loaded.accounts[0]);
    assert.equal(collected.messages[0].text, "ping");
    assert.equal(JSON.stringify(collected).includes(fixtureToken), false);

    const originalFetch = globalThis.fetch;
    let seen;
    globalThis.fetch = async (url, init) => {
      seen = { url, init };
      return { ok: true, status: 200, text: async () => JSON.stringify({ ret: 0 }) };
    };
    try {
      const sent = await sendText("peer-1", "**hello**", "bot-qr");
      assert.equal(sent.ret, 0);
      assert.equal(JSON.stringify(sent).includes(fixtureToken), false);
      const body = JSON.parse(seen.init.body);
      assert.equal(body.msg.to_user_id, "peer-1");
      assert.equal(body.msg.item_list[0].text_item.text, "hello");
      assert.equal(body.msg.context_token, "ctx-2");
      assert.equal(new URL(seen.url).pathname, "/ilink/bot/sendmessage");
      assert.equal(String(seen.init.headers.Authorization).startsWith("Bearer "), true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
