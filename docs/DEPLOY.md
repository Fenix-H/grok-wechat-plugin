# Box deploy

The WeChat account is already bound. Its bot token stays in `~/.grok-wechat/account.json` on the persistent box. This package does not read, print, or replace that file. Do not set a different `GROK_WECHAT_HOME`, or the server will not see the existing login.

Node.js 20+ only. No npm install. Unpack the plugin directory, not the state directory.

```bash
tar -xzf grok-wechat-plugin-text-media.tar.gz -C "$HOME"
cd "$HOME/grok-wechat-plugin"
export GROK_WECHAT_HOME="$HOME/.grok-wechat"
chmod 700 "$GROK_WECHAT_HOME"
chmod 600 "$GROK_WECHAT_HOME/account.json"
```

Do not `cat` `account.json`.

## Text

Inbound text is saved by the monitor. Outbound text needs one inbound message from that peer first, so a `context_token` exists.

```bash
node server/index.js --poll-text
node server/index.js --send-text --to '<from_user_id>' --text 'hello'
node server/index.js --ensure-monitor
node server/index.js --drain-inbox
```

`--ensure-monitor` starts one detached long poll. Do not add a 5-minute model routine.

## Webhook

Set both variables in the environment. The key is not a command argument and is not written to `wake.json`.

```bash
export GROK_WECHAT_WAKE_URL='https://<webhook-host>/<path>'
export GROK_WECHAT_WAKE_KEY='<secret>'
node server/index.js --set-wake
```

The URL must be the same https address the process will POST to later. Private, loopback, and link-local hosts are refused. The configuration probe does not send the key. Omit these variables to keep text in the local inbox without a wake POST.

Restart the monitor from a shell that still has `GROK_WECHAT_HOME` and, if used, the wake variables.

## Media

Inbound images accept `image_item.aeskey` (32 hex) or `media.aes_key` (base64 of 16 bytes, or base64 of that hex). If both image keys are absent, the download is treated as a plaintext image. Video and file items still require `media.aes_key`. Saved files use the container detected from the bytes (for example `.jpg`, `.png`, `.mp4`, `.webm`), not `.bin`.

Outbound files must be under `~/.grok-wechat/media` or `GROK_WECHAT_SEND_ROOTS` (absolute directories, not the state directory).

Offline tests do not show that a live WeChat text, image, or video roundtrip succeeded.
