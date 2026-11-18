import { collectInbound, getUpdates, loginStart, loginWait, sendText, setAccountWake } from "./ilink.js";
import { interpretQrImage, saveQrArtifact } from "./media.js";
import { assertPublicJson } from "./safety.js";
import { drainInbox, listAccounts } from "./store.js";

const TEXT_FLAGS = ["--write-login-qr", "--login-wait", "--poll-text", "--send-text", "--drain-inbox", "--set-wake"];

export function isTextCommand(argv) {
  return TEXT_FLAGS.some((flag) => argv.includes(flag));
}

function argValue(argv, flag) {
  const index = argv.indexOf(flag);
  if (index < 0) return "";
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) return "";
  return value;
}

export function presentQr(started, saved) {
  return assertPublicJson({
    qrcode: typeof started?.qrcode === "string" ? started.qrcode : "",
    next: "wechat_login_wait",
    kind: saved?.kind || "",
    path: saved?.path || "",
    content_type: saved?.content_type || "",
    image_url: saved?.kind === "url" ? saved.url || "" : "",
  });
}

export function presentLogin(result) {
  return assertPublicJson({
    logged_in: Boolean(result?.logged_in),
    expired: Boolean(result?.expired),
    status: result?.status || "",
    ilink_bot_id: result?.ilink_bot_id || "",
    ilink_user_id: result?.ilink_user_id || "",
    next: result?.next || "",
    hint: result?.hint || "",
  });
}

export function presentInbound(message) {
  return assertPublicJson({
    from_user_id: message?.from_user_id || "",
    ilink_bot_id: message?.ilink_bot_id || "",
    ilink_user_id: message?.ilink_user_id || "",
    text: message?.text || "",
    error: message?.error || "",
    items: (message?.items || []).map((item) => ({
      type: item.type || "",
      text: item.text || "",
      path: item.path || null,
      content_type: item.content_type || "",
      extension: item.extension || "",
      detected_kind: item.detected_kind || "",
      error: item.error || "",
      name: item.name || "",
    })),
  });
}

export function presentSend(result) {
  return assertPublicJson({
    to_user_id: result?.to_user_id || "",
    ilink_bot_id: result?.ilink_bot_id || "",
    ilink_user_id: result?.ilink_user_id || "",
    ret: result?.ret ?? 0,
  });
}

export async function runTextCommand(argv) {
  if (argv.includes("--write-login-qr")) {
    const started = await loginStart();
    if (started?.bot_token || started?.token) throw new Error("登录出码响应异常");
    const interpreted = interpretQrImage(started.image || "");
    const saved = saveQrArtifact(interpreted, argValue(argv, "--write-login-qr") || undefined);
    return presentQr(started, saved);
  }
  if (argv.includes("--login-wait")) {
    const timeout = Number(argValue(argv, "--timeout-ms") || 120_000);
    const result = await loginWait(Number.isFinite(timeout) ? timeout : 120_000, argValue(argv, "--qrcode") || undefined);
    return presentLogin(result);
  }
  if (argv.includes("--poll-text")) {
    const accounts = listAccounts();
    if (!accounts.length) throw new Error("未登录。先完成扫码绑定");
    const messages = [];
    for (const account of accounts) {
      const raw = await getUpdates(account);
      if (raw.session_expired) {
        messages.push({ ilink_bot_id: account.ilinkBotId || "", error: "session expired", text: "", items: [] });
        continue;
      }
      const collected = await collectInbound(raw.msgs || [], account);
      for (const message of collected.messages) messages.push(presentInbound(message));
    }
    return assertPublicJson({ messages });
  }
  if (argv.includes("--drain-inbox")) {
    return assertPublicJson({ messages: drainInbox().map((message) => presentInbound(message)) });
  }
  if (argv.includes("--set-wake")) {
    return assertPublicJson(await setAccountWake(argValue(argv, "--ilink-bot-id") || undefined, undefined, undefined));
  }
  if (argv.includes("--send-text")) {
    const to = argValue(argv, "--to");
    const text = argValue(argv, "--text");
    if (!to || !text) throw new Error("需要 --to 和 --text");
    return presentSend(await sendText(to, text, argValue(argv, "--ilink-bot-id") || undefined));
  }
  throw new Error("未知文本命令");
}
