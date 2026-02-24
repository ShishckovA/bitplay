# BitPlay Debug Data Collection

Short checklist for collecting data before debugging.

## 1) Player diagnostics (API snapshot)

Run from project root:

```bash
set -a; source .env; set +a
BASE_URL="http://127.0.0.1:3347"
SESSION_ID="<put_session_id_here_or_leave_empty>"

curl --noproxy '*' -s \
  -u "$BITPLAY_AUTH_USERNAME:$BITPLAY_AUTH_PASSWORD" \
  "$BASE_URL/api/v1/player-diagnostics?format=json&limit=100&sessionId=$SESSION_ID" \
  > debug-player-diagnostics.json
```

If auth is disabled, remove `-u "$BITPLAY_AUTH_USERNAME:$BITPLAY_AUTH_PASSWORD"`.

## 2) Main container logs (`bitplay`)

```bash
docker compose ps
docker compose logs --timestamps --since=30m bitplay > debug-bitplay.log
docker compose logs --tail=500 bitplay > debug-bitplay-tail.log
```

If the app was started via `docker run` (not Compose):

```bash
docker logs --since=30m --timestamps bitplay > debug-bitplay.log
```

For live reproduction:

```bash
docker compose logs -f --timestamps bitplay
```

## 3) Optional: focus logs by session/request

```bash
SESSION_ID="<session_id>"
REQUEST_ID="<req-... optional>"

rg -n "$SESSION_ID|$REQUEST_ID|player-diagnostics|/diagnostics|/transcode|/stream" debug-bitplay.log \
  > debug-bitplay-focus.log
```

## 4) Optional: raw diagnostics file from inside container

```bash
docker compose exec bitplay sh -lc \
  'wc -l /tmp/bitplay-player-diagnostics.ndjson; tail -n 200 /tmp/bitplay-player-diagnostics.ndjson' \
  > debug-player-diagnostics-tail.ndjson
```

## 5) What to send for debugging

- `debug-player-diagnostics.json`
- `debug-bitplay.log`
- `debug-bitplay-tail.log`
- `debug-bitplay-focus.log` (if generated)
- Reproduction steps and exact time window (with timezone)
