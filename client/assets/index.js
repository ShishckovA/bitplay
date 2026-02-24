const getLanguage = (code) => {
  const lang = new Intl.DisplayNames(["en"], { type: "language" });
  return lang.of(code);
};

const getVideoMimeType = (fileName) => {
  const name = String(fileName || "").toLowerCase();
  if (name.endsWith(".mp4") || name.endsWith(".m4v")) return "video/mp4";
  if (name.endsWith(".webm")) return "video/webm";
  // MKV/AVI are handled through server compatibility transcode by default.
  return "";
};

const getVideoExtension = (fileName) => {
  const name = String(fileName || "").toLowerCase();
  const dotIndex = name.lastIndexOf(".");
  if (dotIndex < 0) return "";
  return name.slice(dotIndex);
};

const videoFilePriority = (fileName) => {
  const ext = getVideoExtension(fileName);
  if (ext === ".mp4" || ext === ".m4v") return 0;
  if (ext === ".webm") return 1;
  if (ext === ".mkv") return 2;
  if (ext === ".avi") return 3;
  return 100;
};

const shouldUseCompatibilityTranscode = (fileName) => {
  const ext = getVideoExtension(fileName);
  return ext === ".mkv" || ext === ".avi";
};

let activePlayerDiagnosticsSink = null;

const dispatchPlayerLogToDiagnostics = (level, args) => {
  if (typeof activePlayerDiagnosticsSink !== "function") return;
  const event = typeof args[0] === "string" ? args[0] : "log";
  const details = typeof args[0] === "string" ? args.slice(1) : args;
  try {
    activePlayerDiagnosticsSink({
      level,
      event,
      details,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("[bitplay-player] diagnostics sink failed", error);
  }
};

const playerDebug = (...args) => {
  console.log("[bitplay-player]", ...args);
  dispatchPlayerLogToDiagnostics("debug", args);
};

const playerWarn = (...args) => {
  console.warn("[bitplay-player]", ...args);
  dispatchPlayerLogToDiagnostics("warn", args);
};

const playerErrorLog = (...args) => {
  console.error("[bitplay-player]", ...args);
  dispatchPlayerLogToDiagnostics("error", args);
};

const SOURCE_PROBE_TIMEOUT_MS = 8000;
const PLAYER_DIAGNOSTICS_STORAGE_KEY = "bitplay_player_diagnostics_enabled";
const PLAYER_DIAGNOSTICS_TICK_MS = 1000;
const PLAYER_DIAGNOSTICS_POLL_MS = 2500;
const PLAYER_DIAGNOSTICS_MAX_EVENTS = 80;
const PLAYER_DIAGNOSTICS_UPLOAD_TIMEOUT_MS = 4500;
const PLAYER_DIAGNOSTICS_UPLOAD_MIN_INTERVAL_MS = 3500;
const PLAYER_DIAGNOSTICS_UPLOAD_PERIODIC_MS = 15000;
const PLAYER_STALL_RECOVERY_TICK_MS = 1000;
const PLAYER_STALL_RECOVERY_STUCK_SECONDS = 12;
const PLAYER_STALL_RECOVERY_SEEK_BOOTSTRAP_STUCK_SECONDS = 45;
const PLAYER_STALL_RECOVERY_MIN_COOLDOWN_MS = 9000;
const PLAYER_STALL_RECOVERY_MAX_ATTEMPTS_PER_SOURCE = 8;
const PLAYER_COMPAT_BOOTSTRAP_RETRY_DELAY_MS = 2500;
const PLAYER_COMPAT_BOOTSTRAP_MAX_ATTEMPTS = 16;
const PLAYER_COMPAT_BOOTSTRAP_SEEK_BACKOFF_BASE_SECONDS = 2.5;
const PLAYER_COMPAT_BOOTSTRAP_SEEK_BACKOFF_MAX_SECONDS = 180;
const PLAYER_COMPAT_VIRTUAL_NATIVE_DURATION_THRESHOLD_SECONDS = 6;
const PLAYER_COMPAT_VIRTUAL_SEEK_DEBOUNCE_MS = 220;
const PLAYER_COMPAT_VIRTUAL_SOURCE_SETTLE_BYPASS_MS = 1200;
const PLAYER_COMPAT_VIRTUAL_SOURCE_SWITCH_TOLERANCE_SECONDS = 0.2;

const readyStateText = (state) => {
  switch (state) {
    case 0:
      return "HAVE_NOTHING";
    case 1:
      return "HAVE_METADATA";
    case 2:
      return "HAVE_CURRENT_DATA";
    case 3:
      return "HAVE_FUTURE_DATA";
    case 4:
      return "HAVE_ENOUGH_DATA";
    default:
      return "UNKNOWN";
  }
};

const networkStateText = (state) => {
  switch (state) {
    case 0:
      return "NETWORK_EMPTY";
    case 1:
      return "NETWORK_IDLE";
    case 2:
      return "NETWORK_LOADING";
    case 3:
      return "NETWORK_NO_SOURCE";
    default:
      return "UNKNOWN";
  }
};

const clampNumber = (value, fallback = 0) => {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  return value;
};

const formatSeconds = (value) => clampNumber(value).toFixed(1) + "s";

const formatBytes = (value) => {
  const num = clampNumber(value);
  if (num <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unitIndex = 0;
  let scaled = num;
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024;
    unitIndex += 1;
  }
  const precision = unitIndex === 0 ? 0 : unitIndex === 1 ? 1 : 2;
  return scaled.toFixed(precision) + " " + units[unitIndex];
};

const formatRate = (value) => formatBytes(value) + "/s";

const formatTimeOfDay = (isoString) => {
  if (!isoString) return "-";
  const date = new Date(isoString);
  if (!Number.isFinite(date.getTime())) return "-";
  return date.toLocaleTimeString([], { hour12: false });
};

const toTimeRangesArray = (ranges) => {
  if (!ranges || typeof ranges.length !== "number") return [];
  const out = [];
  for (let i = 0; i < ranges.length; i += 1) {
    try {
      out.push({
        start: clampNumber(ranges.start(i)),
        end: clampNumber(ranges.end(i)),
      });
    } catch (error) {
      break;
    }
  }
  return out;
};

const createSingleTimeRange = (start, end) => {
  const normalizedStart = Math.max(0, clampNumber(start, 0));
  const normalizedEnd = Math.max(normalizedStart, clampNumber(end, normalizedStart));
  const hasRange = normalizedEnd > normalizedStart;
  return {
    length: hasRange ? 1 : 0,
    start(index) {
      if (!hasRange || index !== 0) {
        throw new Error("INDEX_SIZE_ERR");
      }
      return normalizedStart;
    },
    end(index) {
      if (!hasRange || index !== 0) {
        throw new Error("INDEX_SIZE_ERR");
      }
      return normalizedEnd;
    },
  };
};

const formatRanges = (ranges) => {
  if (!Array.isArray(ranges) || ranges.length === 0) return "[]";
  return (
    "[" +
    ranges
      .map((range) => clampNumber(range.start).toFixed(1) + "-" + clampNumber(range.end).toFixed(1))
      .join(", ") +
    "]"
  );
};

const getBufferAhead = (ranges, currentTime) => {
  if (!Array.isArray(ranges) || ranges.length === 0) return 0;
  for (const range of ranges) {
    if (currentTime >= range.start && currentTime <= range.end) {
      return Math.max(0, range.end - currentTime);
    }
  }
  return 0;
};

const addQueryParam = (rawSrc, key, value) => {
  if (!rawSrc) return rawSrc;
  try {
    const normalized = new URL(rawSrc, window.location.origin);
    normalized.searchParams.set(key, value);
    if (/^https?:\/\//i.test(rawSrc)) {
      return normalized.toString();
    }
    return normalized.pathname + normalized.search + normalized.hash;
  } catch (error) {
    const separator = rawSrc.includes("?") ? "&" : "?";
    return rawSrc + separator + encodeURIComponent(key) + "=" + encodeURIComponent(value);
  }
};

const parseSourceStartSeconds = (rawSrc) => {
  if (!rawSrc) return 0;
  try {
    const normalized = new URL(rawSrc, window.location.origin);
    return clampNumber(Number.parseFloat(normalized.searchParams.get("start") || "0"), 0);
  } catch (error) {
    return 0;
  }
};

const parseDurationHintSeconds = (value) => {
  if (typeof value === "number") {
    return Number.isFinite(value) && value > 0 ? value : 0;
  }
  if (typeof value !== "string") return 0;
  const parsed = Number.parseFloat(value.trim());
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return parsed;
};

const readDurationHintFromProbe = (probe) => {
  if (!probe || typeof probe !== "object") return 0;
  return parseDurationHintSeconds(
    probe.durationHintSeconds ||
      probe.bitplayDurationSeconds ||
      probe.durationHint ||
      ""
  );
};

const summarizeForDiagnostics = (value, depth = 0) => {
  if (value == null) return value;
  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
    };
  }
  const valueType = typeof value;
  if (valueType === "string") {
    return value.length > 220 ? value.slice(0, 217) + "..." : value;
  }
  if (valueType === "number" || valueType === "boolean") return value;
  if (Array.isArray(value)) {
    const items = value.slice(0, 6).map((item) => summarizeForDiagnostics(item, depth + 1));
    if (value.length > 6) items.push("...+" + (value.length - 6));
    return items;
  }
  if (valueType === "object") {
    if (depth >= 2) return "[Object]";
    const keys = Object.keys(value);
    const out = {};
    keys.slice(0, 10).forEach((key) => {
      out[key] = summarizeForDiagnostics(value[key], depth + 1);
    });
    if (keys.length > 10) {
      out.__extraKeys = keys.length - 10;
    }
    return out;
  }
  return String(value);
};

const stringifyDiagnosticsValue = (value) => {
  try {
    return JSON.stringify(summarizeForDiagnostics(value));
  } catch (error) {
    return String(value);
  }
};

const createPlaybackDiagnostics = (sessionId) => {
  const params = new URLSearchParams(window.location.search);
  const debugQuery = (params.get("playerDebug") || "").toLowerCase();
  if (debugQuery === "1" || debugQuery === "true" || debugQuery === "on") {
    localStorage.setItem(PLAYER_DIAGNOSTICS_STORAGE_KEY, "1");
  }
  if (debugQuery === "0" || debugQuery === "false" || debugQuery === "off") {
    localStorage.setItem(PLAYER_DIAGNOSTICS_STORAGE_KEY, "0");
  }

  let enabled = localStorage.getItem(PLAYER_DIAGNOSTICS_STORAGE_KEY) === "1";
  let mediaElement = null;
  let localTickId = null;
  let serverPollId = null;
  let pollingDiagnostics = false;
  let latestMediaSnapshot = null;
  let latestServerDiagnostics = null;
  let latestServerError = "";
  let latestSourceDiagnostics = null;
  let latestError = null;
  let lastSampleTimeMs = 0;
  let lastCurrentTime = 0;
  let playheadStuckSeconds = 0;
  let uploadTimerId = null;
  let uploadFlushTimerId = null;
  let uploadInFlight = false;
  let pendingUpload = null;
  let lastUploadAttemptAt = 0;
  let lastUploadSuccessAt = "";
  let lastUploadError = "";
  let uploadsSucceeded = 0;
  let uploadsFailed = 0;
  const events = [];
  const counters = {
    waiting: 0,
    stalled: 0,
    errors: 0,
  };

  const root = document.createElement("section");
  root.style.width = "100%";
  root.style.marginTop = "10px";

  const controls = document.createElement("div");
  controls.style.display = "flex";
  controls.style.alignItems = "center";
  controls.style.gap = "8px";
  controls.style.flexWrap = "wrap";

  const toggleButton = document.createElement("button");
  toggleButton.type = "button";
  toggleButton.className = "btn small";

  const copyButton = document.createElement("button");
  copyButton.type = "button";
  copyButton.className = "btn small";
  copyButton.textContent = "Copy report";

  const clearButton = document.createElement("button");
  clearButton.type = "button";
  clearButton.className = "btn small";
  clearButton.textContent = "Clear log";

  const statusLabel = document.createElement("span");
  statusLabel.style.fontSize = "12px";
  statusLabel.style.opacity = "0.75";

  controls.appendChild(toggleButton);
  controls.appendChild(copyButton);
  controls.appendChild(clearButton);
  controls.appendChild(statusLabel);

  const panel = document.createElement("pre");
  panel.style.margin = "8px 0 0";
  panel.style.padding = "12px";
  panel.style.borderRadius = "8px";
  panel.style.maxHeight = "340px";
  panel.style.overflow = "auto";
  panel.style.whiteSpace = "pre-wrap";
  panel.style.wordBreak = "break-word";
  panel.style.fontFamily = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
  panel.style.fontSize = "12px";
  panel.style.lineHeight = "1.45";
  panel.style.background = "rgba(0, 0, 0, 0.85)";
  panel.style.color = "#d7fce2";
  panel.style.border = "1px solid rgba(255, 255, 255, 0.2)";

  root.appendChild(controls);
  root.appendChild(panel);

  const ensureMounted = () => {
    if (root.isConnected) return;
    const main = document.querySelector("main");
    if (!main) return;
    main.appendChild(root);
  };

  const appendEvent = (level, event, details) => {
    events.unshift({
      at: new Date().toISOString(),
      level,
      event,
      details: Array.isArray(details) ? details.map((item) => summarizeForDiagnostics(item)) : [],
    });
    if (events.length > PLAYER_DIAGNOSTICS_MAX_EVENTS) {
      events.pop();
    }
  };

  const updateStallEstimate = (snapshot) => {
    if (!snapshot) {
      playheadStuckSeconds = 0;
      return;
    }
    const nowMs = Date.now();
    const elapsed = lastSampleTimeMs > 0 ? (nowMs - lastSampleTimeMs) / 1000 : 0;
    lastSampleTimeMs = nowMs;
    const isPlaying = snapshot.paused === false && snapshot.ended === false && snapshot.seeking === false;
    if (!isPlaying || elapsed <= 0) {
      playheadStuckSeconds = 0;
      lastCurrentTime = snapshot.currentTime;
      return;
    }
    const delta = Math.abs(snapshot.currentTime - lastCurrentTime);
    if (delta < 0.04) {
      playheadStuckSeconds += elapsed;
    } else {
      playheadStuckSeconds = 0;
    }
    lastCurrentTime = snapshot.currentTime;
  };

  const collectMediaSnapshot = () => {
    if (!mediaElement) return null;
    const bufferedRanges = toTimeRangesArray(mediaElement.buffered);
    const currentTime = clampNumber(mediaElement.currentTime);
    const duration = clampNumber(mediaElement.duration);
    const bufferAhead = getBufferAhead(bufferedRanges, currentTime);
    const quality = typeof mediaElement.getVideoPlaybackQuality === "function"
      ? mediaElement.getVideoPlaybackQuality()
      : null;
    const droppedFrames = quality ? clampNumber(quality.droppedVideoFrames) : null;
    const totalFrames = quality ? clampNumber(quality.totalVideoFrames) : null;

    return {
      src: mediaElement.currentSrc || "",
      currentTime,
      duration,
      paused: !!mediaElement.paused,
      seeking: !!mediaElement.seeking,
      ended: !!mediaElement.ended,
      playbackRate: clampNumber(mediaElement.playbackRate, 1),
      readyState: clampNumber(mediaElement.readyState),
      networkState: clampNumber(mediaElement.networkState),
      bufferedRanges,
      bufferAhead,
      droppedFrames,
      totalFrames,
      muted: !!mediaElement.muted,
      volume: clampNumber(mediaElement.volume, 1),
      videoWidth: clampNumber(mediaElement.videoWidth),
      videoHeight: clampNumber(mediaElement.videoHeight),
    };
  };

  const buildReport = () => {
    const lines = [];
    lines.push("BitPlay Player Diagnostics");
    lines.push("time: " + new Date().toISOString());
    lines.push("session: " + sessionId);
    lines.push("mode: " + (enabled ? "enabled" : "disabled"));
    lines.push("");

    if (latestMediaSnapshot) {
      lines.push("Playback");
      lines.push("src: " + (latestMediaSnapshot.src || "-"));
      lines.push(
        "state: " +
          (latestMediaSnapshot.paused ? "paused" : "playing") +
          ", seeking=" +
          latestMediaSnapshot.seeking +
          ", ended=" +
          latestMediaSnapshot.ended
      );
      lines.push(
        "time: " +
          formatSeconds(latestMediaSnapshot.currentTime) +
          " / " +
          formatSeconds(latestMediaSnapshot.duration)
      );
      lines.push("buffer ahead: " + formatSeconds(latestMediaSnapshot.bufferAhead));
      lines.push("buffered: " + formatRanges(latestMediaSnapshot.bufferedRanges));
      lines.push(
        "ready/network: " +
          latestMediaSnapshot.readyState +
          " " +
          readyStateText(latestMediaSnapshot.readyState) +
          " / " +
          latestMediaSnapshot.networkState +
          " " +
          networkStateText(latestMediaSnapshot.networkState)
      );
      lines.push(
        "playbackRate: " +
          latestMediaSnapshot.playbackRate.toFixed(2) +
          ", muted=" +
          latestMediaSnapshot.muted +
          ", volume=" +
          latestMediaSnapshot.volume.toFixed(2)
      );
      lines.push(
        "resolution: " +
          latestMediaSnapshot.videoWidth +
          "x" +
          latestMediaSnapshot.videoHeight +
          ", dropped/total frames: " +
          (latestMediaSnapshot.droppedFrames ?? "-") +
          "/" +
          (latestMediaSnapshot.totalFrames ?? "-")
      );
      lines.push("playhead stuck estimate: " + formatSeconds(playheadStuckSeconds));
    } else {
      lines.push("Playback");
      lines.push("waiting for media snapshot...");
    }

    lines.push("");
    lines.push("Events");
    lines.push(
      "waiting=" + counters.waiting + ", stalled=" + counters.stalled + ", errors=" + counters.errors
    );
    if (latestError) {
      lines.push("last error: " + stringifyDiagnosticsValue(latestError));
    }

    lines.push("");
    lines.push("Torrent");
    if (latestServerDiagnostics) {
      lines.push("name: " + (latestServerDiagnostics.torrentName || "-"));
      lines.push(
        "progress: " +
          clampNumber(latestServerDiagnostics.progress).toFixed(2) +
          "% (" +
          formatBytes(latestServerDiagnostics.bytesCompleted) +
          " / " +
          formatBytes(latestServerDiagnostics.torrentLengthBytes) +
          ")"
      );
      lines.push(
        "peers: total=" +
          clampNumber(latestServerDiagnostics.totalPeers) +
          ", active=" +
          clampNumber(latestServerDiagnostics.activePeers) +
          ", pending=" +
          clampNumber(latestServerDiagnostics.pendingPeers) +
          ", seeders=" +
          clampNumber(latestServerDiagnostics.connectedSeeders)
      );
      lines.push(
        "rates: down=" +
          formatRate(latestServerDiagnostics.downloadRateBps) +
          ", useful=" +
          formatRate(latestServerDiagnostics.usefulDownloadRateBps) +
          ", up=" +
          formatRate(latestServerDiagnostics.uploadRateBps)
      );
    } else if (latestServerError) {
      lines.push("server diagnostics error: " + latestServerError);
    } else {
      lines.push("waiting for server diagnostics...");
    }

    if (latestSourceDiagnostics) {
      lines.push("");
      lines.push("Source probe");
      lines.push(stringifyDiagnosticsValue(latestSourceDiagnostics));
    }

    lines.push("");
    lines.push("Remote upload");
    lines.push("uploads: ok=" + uploadsSucceeded + ", failed=" + uploadsFailed);
    lines.push("last success: " + (lastUploadSuccessAt || "-"));
    if (lastUploadError) {
      lines.push("last upload error: " + lastUploadError);
    }

    lines.push("");
    lines.push("Recent events");
    if (events.length === 0) {
      lines.push("- no events yet");
    } else {
      events.slice(0, 12).forEach((entry) => {
        const payload =
          entry.details && entry.details.length > 0
            ? " " + stringifyDiagnosticsValue(entry.details)
            : "";
        lines.push("- " + entry.at + " [" + entry.level + "] " + entry.event + payload);
      });
    }

    return lines.join("\n");
  };

  const buildUploadPayload = (reason, includeReport) => {
    const mediaSummary = latestMediaSnapshot
      ? {
          src: latestMediaSnapshot.src,
          currentTime: latestMediaSnapshot.currentTime,
          duration: latestMediaSnapshot.duration,
          bufferAhead: latestMediaSnapshot.bufferAhead,
          readyState: latestMediaSnapshot.readyState,
          networkState: latestMediaSnapshot.networkState,
          paused: latestMediaSnapshot.paused,
          seeking: latestMediaSnapshot.seeking,
          ended: latestMediaSnapshot.ended,
          playbackRate: latestMediaSnapshot.playbackRate,
          droppedFrames: latestMediaSnapshot.droppedFrames,
          totalFrames: latestMediaSnapshot.totalFrames,
        }
      : null;

    const payload = {
      sessionId,
      kind: "player-diagnostics",
      reason: reason || "unknown",
      clientTimestamp: new Date().toISOString(),
      url: window.location.href,
      diagnosticsEnabled: enabled,
      visibilityState: document.visibilityState || "",
      counters: { ...counters },
      playheadStuckSeconds,
      media: mediaSummary,
      serverDiagnostics: latestServerDiagnostics ? { ...latestServerDiagnostics } : null,
      serverDiagnosticsError: latestServerError || "",
      sourceDiagnostics: summarizeForDiagnostics(latestSourceDiagnostics),
      latestError: summarizeForDiagnostics(latestError),
      recentEvents: summarizeForDiagnostics(events.slice(0, 12)),
    };

    if (includeReport) {
      payload.report = buildReport();
    }

    return payload;
  };

  const flushUploadQueue = async () => {
    if (uploadInFlight || !pendingUpload) return;

    const nextUpload = pendingUpload;
    const now = Date.now();
    const elapsed = now - lastUploadAttemptAt;
    if (!nextUpload.force && elapsed < PLAYER_DIAGNOSTICS_UPLOAD_MIN_INTERVAL_MS) {
      if (!uploadFlushTimerId) {
        uploadFlushTimerId = setTimeout(() => {
          uploadFlushTimerId = null;
          flushUploadQueue().catch(() => {});
        }, PLAYER_DIAGNOSTICS_UPLOAD_MIN_INTERVAL_MS - elapsed + 40);
      }
      return;
    }

    pendingUpload = null;
    if (uploadFlushTimerId) {
      clearTimeout(uploadFlushTimerId);
      uploadFlushTimerId = null;
    }

    const payload = buildUploadPayload(nextUpload.reason, nextUpload.includeReport);
    uploadInFlight = true;
    lastUploadAttemptAt = now;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PLAYER_DIAGNOSTICS_UPLOAD_TIMEOUT_MS);
    try {
      const response = await fetch("/api/v1/player-diagnostics", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error("status " + response.status);
      }
      uploadsSucceeded += 1;
      lastUploadSuccessAt = new Date().toISOString();
      lastUploadError = "";
    } catch (error) {
      uploadsFailed += 1;
      lastUploadError = String(error);
      console.warn("[bitplay-player] diagnostics upload failed", error);
    } finally {
      clearTimeout(timeout);
      uploadInFlight = false;
      if (pendingUpload) {
        flushUploadQueue().catch(() => {});
      }
      if (enabled) {
        render();
      }
    }
  };

  const queueUpload = (reason, options = {}) => {
    const nextUpload = {
      reason: reason || "unknown",
      includeReport: !!options.includeReport,
      force: !!options.force,
    };

    if (!pendingUpload) {
      pendingUpload = nextUpload;
    } else {
      pendingUpload = {
        reason: nextUpload.reason,
        includeReport: pendingUpload.includeReport || nextUpload.includeReport,
        force: pendingUpload.force || nextUpload.force,
      };
    }

    flushUploadQueue().catch(() => {});
  };

  const render = () => {
    const text = buildReport();
    panel.textContent = text;
    statusLabel.textContent =
      (enabled ? "Diagnostics live" : "Diagnostics hidden") +
      " | upload ok=" +
      uploadsSucceeded +
      " fail=" +
      uploadsFailed +
      " last=" +
      formatTimeOfDay(lastUploadSuccessAt);
  };

  const pollServerDiagnostics = async () => {
    if (pollingDiagnostics || !sessionId) return;
    pollingDiagnostics = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), SOURCE_PROBE_TIMEOUT_MS);
    try {
      const response = await fetch("/api/v1/torrent/" + sessionId + "/diagnostics", {
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error("status " + response.status);
      }
      latestServerDiagnostics = await response.json();
      latestServerError = "";
    } catch (error) {
      latestServerError = String(error);
      queueUpload("server-diagnostics-error", { includeReport: false });
    } finally {
      clearTimeout(timeout);
      pollingDiagnostics = false;
    }
  };

  const tick = () => {
    latestMediaSnapshot = collectMediaSnapshot();
    updateStallEstimate(latestMediaSnapshot);
    if (enabled) {
      render();
    }
  };

  const startTimers = () => {
    if (!localTickId) {
      localTickId = setInterval(tick, PLAYER_DIAGNOSTICS_TICK_MS);
    }
    if (!serverPollId) {
      serverPollId = setInterval(() => {
        pollServerDiagnostics().then(() => {
          if (enabled) render();
        });
      }, PLAYER_DIAGNOSTICS_POLL_MS);
    }
    if (!uploadTimerId) {
      uploadTimerId = setInterval(() => {
        queueUpload("periodic", { includeReport: false });
      }, PLAYER_DIAGNOSTICS_UPLOAD_PERIODIC_MS);
    }
    tick();
    pollServerDiagnostics().then(() => {
      if (enabled) render();
    });
    queueUpload("session-start", { force: true, includeReport: true });
  };

  const stopTimers = () => {
    if (localTickId) {
      clearInterval(localTickId);
      localTickId = null;
    }
    if (serverPollId) {
      clearInterval(serverPollId);
      serverPollId = null;
    }
    if (uploadTimerId) {
      clearInterval(uploadTimerId);
      uploadTimerId = null;
    }
    if (uploadFlushTimerId) {
      clearTimeout(uploadFlushTimerId);
      uploadFlushTimerId = null;
    }
  };

  const setEnabled = (nextValue) => {
    enabled = !!nextValue;
    localStorage.setItem(PLAYER_DIAGNOSTICS_STORAGE_KEY, enabled ? "1" : "0");
    panel.style.display = enabled ? "block" : "none";
    copyButton.disabled = !enabled;
    clearButton.disabled = !enabled;
    toggleButton.textContent = enabled ? "Hide debug" : "Show debug";
    render();
  };

  toggleButton.addEventListener("click", () => {
    setEnabled(!enabled);
  });

  clearButton.addEventListener("click", () => {
    events.length = 0;
    latestError = null;
    counters.waiting = 0;
    counters.stalled = 0;
    counters.errors = 0;
    queueUpload("user-clear-log", { includeReport: true });
    render();
  });

  copyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(buildReport());
      butterup.toast({
        message: "Diagnostics copied",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "success",
      });
    } catch (error) {
      playerErrorLog("failed to copy diagnostics", { error: String(error) });
      butterup.toast({
        message: "Failed to copy diagnostics",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
    }
  });

  ensureMounted();
  setEnabled(enabled);
  startTimers();

  const onPlayerLog = (entry) => {
    if (!entry) return;
    appendEvent(entry.level || "debug", entry.event || "log", entry.details || []);

    const eventName = entry.event || "log";
    if (eventName === "waiting") counters.waiting += 1;
    if (eventName === "stalled") counters.stalled += 1;
    if (entry.level === "error" || entry.event === "error event" || entry.event === "native media error") {
      counters.errors += 1;
      const firstDetail = Array.isArray(entry.details) && entry.details.length > 0
        ? summarizeForDiagnostics(entry.details[0])
        : null;
      latestError = firstDetail || entry.event;
    }

    const isCriticalEvent =
      eventName === "error event" ||
      eventName === "native media error" ||
      eventName === "retrying playback after player error" ||
      eventName === "stall recovery triggered" ||
      eventName === "stall recovery exhausted" ||
      eventName === "initial play() rejected" ||
      eventName === "retry play() rejected" ||
      eventName === "stall recovery play() rejected";
    if (isCriticalEvent) {
      queueUpload("event:" + eventName, { force: true, includeReport: true });
    } else if (eventName === "waiting" || eventName === "stalled") {
      queueUpload("event:" + eventName, { includeReport: false });
    }

    if (enabled) {
      render();
    }
  };

  activePlayerDiagnosticsSink = onPlayerLog;

  return {
    attachPlayer(nextPlayer) {
      mediaElement = nextPlayer?.el()?.querySelector("video") || null;
      if (!mediaElement) {
        appendEvent("warn", "diagnostics media element missing", []);
      }
      tick();
      queueUpload("player-attached", { force: true, includeReport: true });
      if (enabled) {
        render();
      }
    },
    setSourceDiagnostics(nextDiagnostics) {
      latestSourceDiagnostics = summarizeForDiagnostics(nextDiagnostics);
      queueUpload("source-diagnostics", { includeReport: false });
      if (enabled) {
        render();
      }
    },
    dispose() {
      queueUpload("session-dispose", { force: true, includeReport: true });
      stopTimers();
      if (activePlayerDiagnosticsSink === onPlayerLog) {
        activePlayerDiagnosticsSink = null;
      }
      root.remove();
    },
  };
};

const mediaErrorCodeText = (code) => {
  switch (code) {
    case 1:
      return "MEDIA_ERR_ABORTED";
    case 2:
      return "MEDIA_ERR_NETWORK";
    case 3:
      return "MEDIA_ERR_DECODE";
    case 4:
      return "MEDIA_ERR_SRC_NOT_SUPPORTED";
    default:
      return "MEDIA_ERR_UNKNOWN";
  }
};

const probeMediaSource = async (label, src) => {
  const startedAt = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SOURCE_PROBE_TIMEOUT_MS);

  try {
    const response = await fetch(src, {
      method: "HEAD",
      signal: controller.signal,
    });

    const diagnostic = {
      label,
      src,
      ok: response.ok,
      status: response.status,
      contentType: response.headers.get("Content-Type") || "",
      acceptRanges: response.headers.get("Accept-Ranges") || "",
      contentLength: response.headers.get("Content-Length") || "",
      durationHintSeconds: response.headers.get("X-BitPlay-Duration-Seconds") || "",
      durationMs: Math.round(performance.now() - startedAt),
    };
    playerDebug("source probe response", diagnostic);
    return diagnostic;
  } catch (error) {
    const diagnostic = {
      label,
      src,
      ok: false,
      status: 0,
      error: String(error),
      durationMs: Math.round(performance.now() - startedAt),
    };
    playerErrorLog("source probe failed", diagnostic);
    return diagnostic;
  } finally {
    clearTimeout(timeout);
  }
};

let settings = {
  enableProxy: false,
  proxyUrl: "",
  enableProwlarr: false,
  prowlarrHost: "",
  prowlarrApiKey: "",
  enableJackett: false,
  jackettHost: "",
  jackettApiKey: "",
};

const searchWrapper = document.querySelector("#search-wrapper");
var player = null;
let activePlaybackDiagnostics = null;

function doubleTapFF(options) {
	var videoElement = this
	var videoElementId = this.id();
	document.getElementById(videoElementId).addEventListener("touchstart", tapHandler);
	var tapedTwice = false;
	function tapHandler(e) {
		if (!videoElement.paused()) {

			if (!tapedTwice) {
				tapedTwice = true;
				setTimeout(function () {
					tapedTwice = false;
				}, 300);
				return false;
			}
			e.preventDefault();
			var br = document.getElementById(videoElementId).getBoundingClientRect();


			var x = e.touches[0].clientX - br.left;
			var y = e.touches[0].clientY - br.top;

			if (x <= br.width / 2) {
				videoElement.currentTime(player.currentTime() - 10)
			} else {
				videoElement.currentTime(player.currentTime() + 10)

			}
		}


	}
}
videojs.registerPlugin('doubleTapFF', doubleTapFF);

(async function ($) {
  // toggle dark mode button
  const toggleDarkMode = () => {
    const html = document.querySelector("html");
    html.classList.toggle("dark");
    localStorage.setItem(
      "theme",
      html.classList.contains("dark") ? "dark" : "light"
    );
  };
  const toggleDarkModeButton = document.querySelector("#toggle_theme");
  toggleDarkModeButton.addEventListener("click", toggleDarkMode);

  // handle past button
  const pastButton = document.querySelector("#copy_magnet");
  pastButton.addEventListener("click", async () => {
    navigator.clipboard.readText().then((text) => {
      document.getElementById("magnet").value = text;
    });
  });

  // handle demo button
  const demoButton = document.querySelector("#demo_torrent");
  demoButton.addEventListener("click", async () => {
    document.getElementById("magnet").value =
      "magnet:?xt=urn:btih:08ada5a7a6183aae1e09d831df6748d566095a10&dn=Sintel&tr=udp%3A%2F%2Fexplodie.org%3A6969&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969&tr=udp%3A%2F%2Ftracker.empire-js.us%3A1337&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=wss%3A%2F%2Ftracker.btorrent.xyz&tr=wss%3A%2F%2Ftracker.fastcast.nz&tr=wss%3A%2F%2Ftracker.openwebtorrent.com&ws=https%3A%2F%2Fwebtorrent.io%2Ftorrents%2F&xs=https%3A%2F%2Fwebtorrent.io%2Ftorrents%2Fsintel.torrent";

    document
      .querySelector("#torrent-form")
      .dispatchEvent(new Event("submit"));
  });

  const form = document.querySelector("#torrent-form");
  const savedTorrentsWrapper = document.querySelector("#saved-torrents-wrapper");
  const savedTorrentsSelect = document.querySelector("#saved-torrents");
  const playSavedButton = document.querySelector("#play-saved");

  const loadSavedTorrents = async () => {
    try {
      const response = await fetch("/api/v1/torrents");
      playerDebug("saved torrents response", { status: response.status });
      if (!response.ok) {
        throw new Error("Failed to fetch saved torrents");
      }

      const torrents = await response.json();
      playerDebug("saved torrents payload", {
        count: Array.isArray(torrents) ? torrents.length : 0,
        ids: Array.isArray(torrents) ? torrents.map((t) => t?.id).filter(Boolean) : [],
      });
      savedTorrentsSelect.innerHTML =
        '<option value="">Select saved torrent...</option>';

      if (!Array.isArray(torrents) || torrents.length === 0) {
        savedTorrentsWrapper.classList.add("hidden");
        return;
      }

      torrents.forEach((torrent) => {
        if (!torrent?.magnet) return;
        const option = document.createElement("option");
        option.value = torrent.magnet;
        option.dataset.torrentId = torrent.id || "";
        const fileCount = Array.isArray(torrent.files) ? torrent.files.length : 0;
        const title = torrent.name || torrent.id || "Unnamed torrent";
        option.textContent =
          fileCount > 0 ? `${title} (${fileCount} files)` : title;
        savedTorrentsSelect.appendChild(option);
      });

      savedTorrentsWrapper.classList.remove("hidden");
    } catch (error) {
      playerErrorLog("Failed to load saved torrents", { error: String(error) });
      savedTorrentsWrapper.classList.add("hidden");
    }
  };

  playSavedButton.addEventListener("click", () => {
    const selectedMagnet = savedTorrentsSelect.value;
    if (!selectedMagnet) {
      butterup.toast({
        message: "Please select a saved torrent",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      return;
    }

    document.querySelector("#magnet").value = selectedMagnet;
    form.dispatchEvent(new Event("submit"));
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const magnet = document.querySelector("#magnet").value;

    if (!magnet) {
      butterup.toast({
        message: "Please enter a magnet link",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      return;
    }

    // clean up previous player
    if (activePlaybackDiagnostics) {
      activePlaybackDiagnostics.dispose();
      activePlaybackDiagnostics = null;
    }
    if (player) {
      player.dispose();
      player = null;
      const vidElm = document.createElement("video");
      vidElm.setAttribute("id", "video-player");
      vidElm.setAttribute("class", "video-js mt-10 w-full");

      document.querySelector("main").appendChild(vidElm);
    }

    form
      .querySelector("button[type=submit]")
      .setAttribute("disabled", "disabled");
    form.querySelector("button[type=submit]").innerHTML = "";
    form.querySelector("button[type=submit]").classList.add("loader");

    const res = await fetch("/api/v1/torrent/add", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ magnet }),
    });
    playerDebug("add torrent response", { status: res.status });

    if (!res.ok) {
      const err = await res.json();
      playerErrorLog("add torrent failed", {
        status: res.status,
        error: err?.error || "unknown",
      });
      butterup.toast({
        message: err.error || "Something went wrong",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      form.querySelector("button[type=submit]").removeAttribute("disabled");
      form.querySelector("button[type=submit]").innerHTML = "Play Now";
      form.querySelector("button[type=submit]").classList.remove("loader");
      document.querySelectorAll("#play-torrent").forEach((el) => {
        el.removeAttribute("disabled");
        el.innerHTML = "Watch";
        el.classList.remove("loader");
      });
      return;
    }

    const { sessionId } = await res.json();
    playerDebug("add torrent success", { sessionId });
    const filesRes = await fetch("/api/v1/torrent/" + sessionId);
    playerDebug("fetch files response", { sessionId, status: filesRes.status });

    if (!filesRes.ok) {
      const err = await filesRes.json();
      playerErrorLog("fetch files failed", {
        sessionId,
        status: filesRes.status,
        error: err?.error || "unknown",
      });
      butterup.toast({
        message: err.error || "Something went wrong",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      form.querySelector("button[type=submit]").removeAttribute("disabled");
      form.querySelector("button[type=submit]").innerHTML = "Play Now";
      form.querySelector("button[type=submit]").classList.remove("loader");
      document.querySelectorAll("#play-torrent").forEach((el) => {
        el.removeAttribute("disabled");
        el.innerHTML = "Watch";
        el.classList.remove("loader");
      });
      return;
    }

    const files = await filesRes.json();

    // Find video file
    const videoFiles = files
      .filter((f) => f.name.match(/\.(mp4|mkv|webm|avi)$/i))
      .sort((left, right) => {
        const priorityDelta = videoFilePriority(left.name) - videoFilePriority(right.name);
        if (priorityDelta !== 0) return priorityDelta;
        return (left.index || 0) - (right.index || 0);
      });

    if (!videoFiles.length) {
      butterup.toast({
        message: "No video file found",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      form.querySelector("button[type=submit]").removeAttribute("disabled");
      form.querySelector("button[type=submit]").innerHTML = "Play Now";
      form.querySelector("button[type=submit]").classList.remove("loader");
      document.querySelectorAll("#play-torrent").forEach((el) => {
        el.removeAttribute("disabled");
        el.innerHTML = "Watch";
        el.classList.remove("loader");
      });
      return;
    }

    const subtitleFiles = files.filter((f) =>
      f.name.match(/\.(srt|vtt|sub)$/i)
    );

    const videoUrls = videoFiles.map((file) => {
      const directSrc = "/api/v1/torrent/" + sessionId + "/stream/" + file.index;
      const compatSrc = "/api/v1/torrent/" + sessionId + "/transcode/" + file.index;
      const preferCompat = shouldUseCompatibilityTranscode(file.name);
      return {
        src: preferCompat ? compatSrc : directSrc,
        directSrc,
        compatSrc,
        preferCompat,
        index: file.index,
        title: file.name,
        extension: getVideoExtension(file.name),
        type: preferCompat ? "video/mp4" : getVideoMimeType(file.name),
        durationHintSeconds: 0,
      };
    });
    playerDebug("prepared sources", {
      sessionId,
      sourceCount: videoUrls.length,
      sources: videoUrls.map((v) => ({
        src: v.src,
        directSrc: v.directSrc,
        compatSrc: v.compatSrc,
        preferCompat: v.preferCompat,
        type: v.type,
        title: v.title,
      })),
    });

    const toVideoJsSource = (video, label) => {
      const source = {
        src: video?.src || "",
        label: label || "",
      };
      if (video?.type) {
        source.type = video.type;
      }
      return source;
    };

    const setVideoDurationHint = (video, hintSeconds, origin) => {
      if (!video) return;
      const parsed = parseDurationHintSeconds(hintSeconds);
      if (parsed <= 0) return;
      if (video.durationHintSeconds && Math.abs(video.durationHintSeconds - parsed) < 0.01) {
        return;
      }
      video.durationHintSeconds = parsed;
      playerDebug("duration hint updated", {
        origin: origin || "unknown",
        title: video.title,
        src: video.src,
        durationHintSeconds: parsed,
      });
    };

    const updateVideoDurationHintFromDiagnostics = (video, diagnostics, origin) => {
      if (!video || !diagnostics) return;
      const directHint = readDurationHintFromProbe(diagnostics.directProbe);
      const compatHint = readDurationHintFromProbe(diagnostics.compatProbe);
      const preferredHint = video.preferCompat ? compatHint || directHint : directHint || compatHint;
      setVideoDurationHint(video, preferredHint, origin);
    };

    const initialVideo = videoUrls[0];
    const initialDirectProbe = await probeMediaSource(
      "initial-direct",
      initialVideo.directSrc || initialVideo.src
    );
    let initialCompatProbe = null;
    if (initialVideo.preferCompat) {
      initialCompatProbe = await probeMediaSource(
        "initial-compat",
        initialVideo.compatSrc || initialVideo.src
      );
    }
    updateVideoDurationHintFromDiagnostics(
      initialVideo,
      {
        directProbe: initialDirectProbe,
        compatProbe: initialCompatProbe,
      },
      "initial"
    );

    let latestSourceDiagnostics = {
      initialDirectProbe,
      initialCompatProbe,
    };
    playerDebug("initial source diagnostics", {
      sessionId,
      diagnostics: latestSourceDiagnostics,
    });

    const initialPrimaryProbe = initialVideo.preferCompat
      ? initialCompatProbe || initialDirectProbe
      : initialDirectProbe;

    if (initialPrimaryProbe?.status === 404) {
      butterup.toast({
        message: "Torrent session is missing on server (404). Re-add this torrent.",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "warning",
      });
      form.querySelector("button[type=submit]").removeAttribute("disabled");
      form.querySelector("button[type=submit]").innerHTML = "Play Now";
      form.querySelector("button[type=submit]").classList.remove("loader");
      document.querySelectorAll("#play-torrent").forEach((el) => {
        el.removeAttribute("disabled");
        el.innerHTML = "Watch";
        el.classList.remove("loader");
      });
      return;
    }

    if (
      initialVideo.preferCompat &&
      initialCompatProbe &&
      !initialCompatProbe.ok &&
      initialCompatProbe.status >= 500
    ) {
      butterup.toast({
        message: "Compatibility mode is unavailable on server. Falling back to direct stream.",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "warning",
      });
      initialVideo.src = initialVideo.directSrc;
      initialVideo.type = "";
      initialVideo.preferCompat = false;
    }

    activePlaybackDiagnostics = createPlaybackDiagnostics(sessionId);
    activePlaybackDiagnostics.setSourceDiagnostics(latestSourceDiagnostics);

    const probeSelectedVideo = async (video, labelPrefix) => {
      if (!video) return null;
      const diagnostics = {
        directProbe: await probeMediaSource(
          labelPrefix + "-direct",
          video.directSrc || video.src
        ),
      };
      if (video.compatSrc) {
        diagnostics.compatProbe = await probeMediaSource(
          labelPrefix + "-compat",
          video.compatSrc
        );
      }
      return diagnostics;
    };

    const normalizeSourceKey = (source) => {
      if (!source) return "";
      try {
        const normalized = new URL(source, window.location.origin);
        return normalized.pathname || "";
      } catch (error) {
        return String(source).split("?")[0].split("#")[0];
      }
    };

    const sourceMatches = (source, target) => {
      const normalizedSource = normalizeSourceKey(source);
      const normalizedTarget = normalizeSourceKey(target);
      if (!normalizedSource || !normalizedTarget) return false;
      return (
        normalizedSource === normalizedTarget ||
        normalizedSource.endsWith(normalizedTarget) ||
        normalizedTarget.endsWith(normalizedSource)
      );
    };

    const findVideoBySrc = (source) => {
      if (!source) return null;
      return (
        videoUrls.find(
          (video) =>
            sourceMatches(source, video.src) ||
            sourceMatches(source, video.directSrc) ||
            sourceMatches(source, video.compatSrc)
        ) ||
        null
      );
    };

    const compatVirtualTimeline = {
      enabled: false,
      video: null,
      durationSeconds: 0,
      baseSeconds: 0,
      sourceStartSeconds: 0,
      anchorAtMs: 0,
      playing: false,
      pendingSeekTargetSeconds: null,
      pendingSeekTimerId: null,
    };
    let compatVirtualSeekBypassUntilMs = 0;
    let nativePlayerCurrentTime = null;
    let nativePlayerDuration = null;
    let mediaElement = null;
    const compatVirtualTechPatches = new WeakMap();

    const getActivePlayerTech = () => {
      if (!player) return null;
      if (typeof player.tech === "function") {
        try {
          return player.tech(true) || player.tech();
        } catch (error) {}
      }
      return player.tech_ || null;
    };

    const getCompatSeekableRange = () => {
      if (!compatVirtualTimeline.enabled || compatVirtualTimeline.durationSeconds <= 0) {
        return null;
      }
      return createSingleTimeRange(0, compatVirtualTimeline.durationSeconds);
    };

    const resolveCompatSourceStartSeconds = () => {
      const sourceStart = parseSourceStartSeconds(player?.currentSrc ? player.currentSrc() : "");
      if (sourceStart > 0) return sourceStart;
      return Math.max(0, clampNumber(compatVirtualTimeline.sourceStartSeconds, 0));
    };

    const resolveCompatNativeSeekSeconds = (virtualSeconds) => {
      const targetSeconds = Math.max(0, clampNumber(virtualSeconds, 0));
      const sourceStartSeconds = resolveCompatSourceStartSeconds();
      let nativeTargetSeconds = Math.max(0, targetSeconds - sourceStartSeconds);

      if (mediaElement) {
        const nativeDuration = clampNumber(mediaElement.duration, 0);
        if (nativeDuration > 0) {
          nativeTargetSeconds = Math.min(
            nativeTargetSeconds,
            Math.max(0, nativeDuration - 0.05)
          );
        } else if (mediaElement.readyState <= 0 && nativeTargetSeconds > 0.25) {
          nativeTargetSeconds = 0;
        }
      }

      return nativeTargetSeconds;
    };

    const readCompatVirtualCurrentTimeFromMedia = () => {
      if (!compatVirtualTimeline.enabled || !mediaElement) return null;
      const nativeCurrentTime = clampNumber(mediaElement.currentTime, -1);
      if (!Number.isFinite(nativeCurrentTime) || nativeCurrentTime < 0) return null;
      return Math.max(0, resolveCompatSourceStartSeconds() + nativeCurrentTime);
    };

    const clearCompatVirtualSeekTimer = () => {
      if (!compatVirtualTimeline.pendingSeekTimerId) return;
      clearTimeout(compatVirtualTimeline.pendingSeekTimerId);
      compatVirtualTimeline.pendingSeekTimerId = null;
    };

    const getCompatVirtualCurrentTime = () => {
      if (!compatVirtualTimeline.enabled) {
        if (typeof nativePlayerCurrentTime === "function") {
          return clampNumber(nativePlayerCurrentTime(), 0);
        }
        return 0;
      }

      const mediaCurrentTime = readCompatVirtualCurrentTimeFromMedia();
      if (mediaCurrentTime != null) {
        let normalized = mediaCurrentTime;
        if (compatVirtualTimeline.durationSeconds > 0) {
          normalized = Math.min(normalized, compatVirtualTimeline.durationSeconds);
        }
        compatVirtualTimeline.baseSeconds = Math.max(0, normalized);
        return Math.max(0, normalized);
      }

      let currentTime = compatVirtualTimeline.baseSeconds;
      if (compatVirtualTimeline.playing && compatVirtualTimeline.anchorAtMs > 0) {
        const elapsed = Math.max(0, (Date.now() - compatVirtualTimeline.anchorAtMs) / 1000);
        const playbackRate = player?.playbackRate ? clampNumber(player.playbackRate(), 1) : 1;
        currentTime += elapsed * playbackRate;
      }
      if (compatVirtualTimeline.durationSeconds > 0) {
        currentTime = Math.min(currentTime, compatVirtualTimeline.durationSeconds);
      }
      return Math.max(0, currentTime);
    };

    const setCompatVirtualBase = (seconds, resumeClock) => {
      let next = clampNumber(seconds, 0);
      if (compatVirtualTimeline.durationSeconds > 0) {
        next = Math.min(next, Math.max(0, compatVirtualTimeline.durationSeconds - 0.05));
      }
      compatVirtualTimeline.baseSeconds = Math.max(0, next);
      compatVirtualTimeline.playing = !!resumeClock;
      compatVirtualTimeline.anchorAtMs = resumeClock ? Date.now() : 0;
    };

    const freezeCompatVirtualClock = () => {
      if (!compatVirtualTimeline.enabled) return;
      setCompatVirtualBase(getCompatVirtualCurrentTime(), false);
    };

    const resumeCompatVirtualClock = () => {
      if (!compatVirtualTimeline.enabled) return;
      setCompatVirtualBase(getCompatVirtualCurrentTime(), true);
    };

    const disableCompatVirtualTimeline = (reason) => {
      if (
        !compatVirtualTimeline.enabled &&
        !compatVirtualTimeline.video &&
        !compatVirtualTimeline.pendingSeekTimerId
      ) {
        return;
      }
      clearCompatVirtualSeekTimer();
      compatVirtualTimeline.enabled = false;
      compatVirtualTimeline.video = null;
      compatVirtualTimeline.durationSeconds = 0;
      compatVirtualTimeline.baseSeconds = 0;
      compatVirtualTimeline.sourceStartSeconds = 0;
      compatVirtualTimeline.anchorAtMs = 0;
      compatVirtualTimeline.playing = false;
      compatVirtualTimeline.pendingSeekTargetSeconds = null;
      compatVirtualSeekBypassUntilMs = 0;
      playerDebug("compat virtual timeline disabled", {
        reason: reason || "",
      });
    };

    const ensureCompatVirtualTechPatched = () => {
      const tech = getActivePlayerTech();
      if (!tech || compatVirtualTechPatches.has(tech)) return;

      const nativeMethods = {
        currentTime: typeof tech.currentTime === "function" ? tech.currentTime.bind(tech) : null,
        setCurrentTime:
          typeof tech.setCurrentTime === "function" ? tech.setCurrentTime.bind(tech) : null,
        duration: typeof tech.duration === "function" ? tech.duration.bind(tech) : null,
        seekable: typeof tech.seekable === "function" ? tech.seekable.bind(tech) : null,
      };
      compatVirtualTechPatches.set(tech, nativeMethods);

      if (nativeMethods.currentTime) {
        tech.currentTime = () => {
          if (!compatVirtualTimeline.enabled) {
            return nativeMethods.currentTime();
          }
          return getCompatVirtualCurrentTime();
        };
      }

      if (nativeMethods.setCurrentTime) {
        tech.setCurrentTime = (seconds) => {
          if (!compatVirtualTimeline.enabled) {
            return nativeMethods.setCurrentTime(seconds);
          }
          const targetSeconds = clampNumber(seconds, getCompatVirtualCurrentTime());
          const nativeTargetSeconds = resolveCompatNativeSeekSeconds(targetSeconds);
          const bypassSeek = Date.now() < compatVirtualSeekBypassUntilMs;
          if (bypassSeek) {
            return nativeMethods.setCurrentTime(nativeTargetSeconds);
          }
          if (!scheduleCompatVirtualSeek(targetSeconds, "tech.setCurrentTime")) {
            return nativeMethods.setCurrentTime(nativeTargetSeconds);
          }
          return targetSeconds;
        };
      }

      if (nativeMethods.duration) {
        tech.duration = () => {
          if (!compatVirtualTimeline.enabled) {
            return nativeMethods.duration();
          }
          return compatVirtualTimeline.durationSeconds > 0
            ? compatVirtualTimeline.durationSeconds
            : nativeMethods.duration();
        };
      }

      if (nativeMethods.seekable) {
        tech.seekable = () => {
          const virtualRange = getCompatSeekableRange();
          if (virtualRange) return virtualRange;
          return nativeMethods.seekable();
        };
      }
    };

    const updateCompatVirtualTimelineForSource = (source, reason) => {
      const targetVideo = findVideoBySrc(source);
      const durationHint = parseDurationHintSeconds(targetVideo?.durationHintSeconds);

      if (!targetVideo?.preferCompat || !targetVideo.compatSrc || durationHint <= 0) {
        disableCompatVirtualTimeline(reason || "missing-compat-duration-hint");
        return;
      }

      const nativeDuration =
        typeof nativePlayerDuration === "function"
          ? clampNumber(nativePlayerDuration(), 0)
          : clampNumber(player?.duration ? player.duration() : 0, 0);
      const nativeDurationLooksHealthy =
        nativeDuration > PLAYER_COMPAT_VIRTUAL_NATIVE_DURATION_THRESHOLD_SECONDS &&
        nativeDuration >= durationHint * 0.85;
      if (nativeDurationLooksHealthy) {
        disableCompatVirtualTimeline(reason || "native-duration-healthy");
        return;
      }

      const startSeconds = parseSourceStartSeconds(source);
      const wasEnabled = compatVirtualTimeline.enabled;
      const previousVideoSrc = compatVirtualTimeline.video?.src || "";
      const previousSourceStartSeconds = clampNumber(compatVirtualTimeline.sourceStartSeconds, 0);

      compatVirtualTimeline.enabled = true;
      compatVirtualTimeline.video = targetVideo;
      compatVirtualTimeline.durationSeconds = durationHint;
      compatVirtualTimeline.sourceStartSeconds = Math.max(0, startSeconds);
      compatVirtualTimeline.pendingSeekTargetSeconds = null;
      const shouldResetBase =
        !wasEnabled ||
        previousVideoSrc !== targetVideo.src ||
        Math.abs(previousSourceStartSeconds - startSeconds) >
          PLAYER_COMPAT_VIRTUAL_SOURCE_SWITCH_TOLERANCE_SECONDS;
      if (shouldResetBase) {
        setCompatVirtualBase(startSeconds, false);
      }

      if (!wasEnabled || previousVideoSrc !== targetVideo.src) {
        playerWarn("compat virtual timeline enabled", {
          reason: reason || "",
          source,
          title: targetVideo.title,
          durationHintSeconds: durationHint,
          nativeDuration,
          startSeconds,
        });
      }
    };

    const setPlayerSource = (source, context = {}) => {
      if (!player || !source?.src) return;
      compatVirtualSeekBypassUntilMs = Date.now() + PLAYER_COMPAT_VIRTUAL_SOURCE_SETTLE_BYPASS_MS;
      compatVirtualTimeline.sourceStartSeconds = Math.max(
        0,
        parseSourceStartSeconds(source.src)
      );
      player.src(source);
      ensureCompatVirtualTechPatched();
      playerDebug("source applied", {
        context,
        source,
      });
    };

    const scheduleCompatVirtualSeek = (targetSeconds, reason) => {
      if (!compatVirtualTimeline.enabled || !compatVirtualTimeline.video?.compatSrc) {
        return false;
      }

      let seekTarget = clampNumber(targetSeconds, getCompatVirtualCurrentTime());
      if (compatVirtualTimeline.durationSeconds > 0) {
        seekTarget = Math.min(
          Math.max(0, seekTarget),
          Math.max(0, compatVirtualTimeline.durationSeconds - 0.05)
        );
      } else {
        seekTarget = Math.max(0, seekTarget);
      }

      clearCompatVirtualSeekTimer();
      compatVirtualTimeline.pendingSeekTargetSeconds = seekTarget;
      compatVirtualTimeline.sourceStartSeconds = seekTarget;
      setCompatVirtualBase(seekTarget, false);

      compatVirtualTimeline.pendingSeekTimerId = setTimeout(() => {
        compatVirtualTimeline.pendingSeekTimerId = null;
        const finalizedTarget = clampNumber(
          compatVirtualTimeline.pendingSeekTargetSeconds,
          seekTarget
        );
        compatVirtualTimeline.pendingSeekTargetSeconds = null;

        const targetVideo =
          compatVirtualTimeline.video || findVideoBySrc(player?.currentSrc?.() || "");
        if (!targetVideo?.compatSrc) {
          return;
        }

        const seekSource = {
          src: addQueryParam(
            addQueryParam(targetVideo.compatSrc, "start", finalizedTarget.toFixed(3)),
            "_bp_seek",
            Date.now().toString(36)
          ),
          type: "video/mp4",
          label: targetVideo.title || "",
        };

        playerWarn("compat virtual seek", {
          reason: reason || "player.currentTime",
          targetSeconds: finalizedTarget,
          source: seekSource.src,
        });

        setPlayerSource(seekSource, {
          reason: "compat-virtual-seek",
          targetSeconds: finalizedTarget,
        });
        player.play().catch((error) => {
          playerErrorLog("compat virtual seek play() rejected", {
            target: targetVideo.src,
            targetSeconds: finalizedTarget,
            error: String(error),
          });
        });
      }, PLAYER_COMPAT_VIRTUAL_SEEK_DEBOUNCE_MS);
      return true;
    };

    const sourceRetryAttempts = {};
    const sourceStallRecoveryAttempts = {};
    const sourceLastRecoveryAt = {};
    const sourceCompatBootstrapRetryAttempts = {};
    const sourceCompatBootstrapRetryTimers = {};
    let lastStallRecoveryAtMs = 0;

    const buildRetryVariants = (video) => {
      if (!video?.src) return [];

      const variants = [];
      const pushVariant = (mode, source) => {
        if (!source?.src) return;
        variants.push({ mode, source });
      };

      pushVariant("initial", toVideoJsSource(video, video.title));

      if (video.type) {
        pushVariant("without-type", {
          src: video.src,
          label: video.title,
        });
      }

      if (video.preferCompat && video.directSrc) {
        let directType = "";
        if (video.extension === ".mkv") directType = "video/x-matroska";
        if (video.extension === ".avi") directType = "video/x-msvideo";

        pushVariant("direct-fallback", {
          src: video.directSrc,
          type: directType,
          label: video.title,
        });
        pushVariant("direct-without-type", {
          src: video.directSrc,
          label: video.title,
        });

        if (video.compatSrc) {
          pushVariant("compatibility-retry", {
            src: video.compatSrc,
            type: "video/mp4",
            label: video.title,
          });
        }
      }

      const uniqueVariants = [];
      const seen = new Set();
      variants.forEach((variant) => {
        const key = (variant.source.src || "") + "|" + (variant.source.type || "");
        if (seen.has(key)) return;
        seen.add(key);
        uniqueVariants.push(variant);
      });

      return uniqueVariants;
    };

    const retryVariantsBySrc = {};
    videoUrls.forEach((video) => {
      retryVariantsBySrc[video.src] = buildRetryVariants(video);
    });

    const prepareRecoverySource = (source, key, attempt) => {
      if (!source?.src) return source;
      return {
        ...source,
        src: addQueryParam(source.src, "_bp_recover", key + "-" + attempt + "-" + Date.now().toString(36)),
      };
    };

    const clearCompatBootstrapRetry = (key, resetAttempts = false) => {
      if (!key) return;
      const timerId = sourceCompatBootstrapRetryTimers[key];
      if (timerId) {
        clearTimeout(timerId);
        delete sourceCompatBootstrapRetryTimers[key];
      }
      if (resetAttempts) {
        sourceCompatBootstrapRetryAttempts[key] = 0;
      }
    };

    const clearPlayerErrorState = (reason) => {
      if (!player || typeof player.error !== "function") return;
      try {
        if (player.error()) {
          playerDebug("clearing player error state", { reason });
          player.error(null);
        }
      } catch (error) {}
    };

    const resolveCompatBootstrapStartSeconds = (activeSource, preferredStartSeconds = 0) => {
      const preferred = clampNumber(preferredStartSeconds, 0);
      if (preferred > 0) return preferred;

      const sourceStart = parseSourceStartSeconds(activeSource);
      if (sourceStart > 0) return sourceStart;

      const pendingSeekStart = clampNumber(compatVirtualTimeline.pendingSeekTargetSeconds, 0);
      if (pendingSeekStart > 0) return pendingSeekStart;

      return Math.max(0, clampNumber(compatVirtualTimeline.sourceStartSeconds, 0));
    };

    const scheduleCompatBootstrapRetry = (
      targetVideo,
      activeSource,
      mediaError,
      preferredStartSeconds = 0
    ) => {
      if (!targetVideo?.preferCompat || !targetVideo.compatSrc || !targetVideo.src) {
        return false;
      }
      if ((mediaError?.code || 0) !== 4) {
        return false;
      }

      const seekStartSeconds = resolveCompatBootstrapStartSeconds(
        activeSource,
        preferredStartSeconds
      );
      const currentTime = player?.currentTime ? clampNumber(player.currentTime(), 0) : 0;
      if (currentTime > 0.5 && seekStartSeconds <= 0) {
        return false;
      }

      const key = targetVideo.src;
      const attempts = sourceCompatBootstrapRetryAttempts[key] || 0;
      if (attempts >= PLAYER_COMPAT_BOOTSTRAP_MAX_ATTEMPTS) {
        return false;
      }
      if (sourceCompatBootstrapRetryTimers[key]) {
        return true;
      }

      const nextAttempt = attempts + 1;
      sourceCompatBootstrapRetryAttempts[key] = nextAttempt;
      const seekBackoffSeconds =
        seekStartSeconds > 0
          ? Math.min(
              PLAYER_COMPAT_BOOTSTRAP_SEEK_BACKOFF_MAX_SECONDS,
              PLAYER_COMPAT_BOOTSTRAP_SEEK_BACKOFF_BASE_SECONDS * nextAttempt
            )
          : 0;

      playerWarn("scheduling compatibility bootstrap retry", {
        activeSource,
        target: key,
        attempt: nextAttempt,
        delayMs: PLAYER_COMPAT_BOOTSTRAP_RETRY_DELAY_MS,
        seekStartSeconds,
        seekBackoffSeconds,
        mediaError,
      });

      sourceCompatBootstrapRetryTimers[key] = setTimeout(() => {
        delete sourceCompatBootstrapRetryTimers[key];

        let compatSourceSrc = addQueryParam(
          targetVideo.compatSrc || targetVideo.src,
          "_bp_boot",
          nextAttempt + "-" + Date.now().toString(36)
        );
        let transcodeStartSeconds = 0;
        if (seekStartSeconds > 0) {
          transcodeStartSeconds = Math.max(0, seekStartSeconds - seekBackoffSeconds);
          compatSourceSrc = addQueryParam(
            compatSourceSrc,
            "start",
            transcodeStartSeconds.toFixed(3)
          );
        }

        const compatSource = {
          src: compatSourceSrc,
          type: "video/mp4",
          label: targetVideo.title || "",
        };

        sourceRetryAttempts[key] = 0;
        sourceStallRecoveryAttempts[key] = 0;
        sourceLastRecoveryAt[key] = 0;

        playerWarn("compatibility bootstrap retry", {
          target: key,
          attempt: nextAttempt,
          source: compatSource.src,
          seekStartSeconds,
          seekBackoffSeconds,
          transcodeStartSeconds,
        });

        setPlayerSource(compatSource, {
          reason: "compat-bootstrap-retry",
          target: key,
          attempt: nextAttempt,
          seekStartSeconds,
          seekBackoffSeconds,
          transcodeStartSeconds,
        });
        player.play().catch((error) => {
          playerErrorLog("compatibility bootstrap play() rejected", {
            target: key,
            attempt: nextAttempt,
            error: String(error),
          });
        });
      }, PLAYER_COMPAT_BOOTSTRAP_RETRY_DELAY_MS);

      return true;
    };

    const retryPlaybackAfterError = (activeSource, mediaError) => {
      const targetVideo = findVideoBySrc(activeSource) || initialVideo;
      if (!targetVideo?.src) return false;

      const seekStartSeconds = parseSourceStartSeconds(activeSource);
      const forceCompatSeekBootstrap =
        targetVideo.preferCompat &&
        seekStartSeconds > 0 &&
        (mediaError?.code || 0) === 4;
      if (forceCompatSeekBootstrap) {
        playerWarn("forcing compatibility bootstrap retry after seek source error", {
          activeSource,
          target: targetVideo.src,
          seekStartSeconds,
          mediaError,
        });
        return scheduleCompatBootstrapRetry(
          targetVideo,
          activeSource,
          mediaError,
          seekStartSeconds
        );
      }

      const key = targetVideo.src;
      const variants = retryVariantsBySrc[key] || [];
      if (variants.length < 2) {
        return scheduleCompatBootstrapRetry(targetVideo, activeSource, mediaError);
      }

      const attempts = sourceRetryAttempts[key] || 0;
      const nextIndex = attempts + 1;
      if (nextIndex >= variants.length) {
        return scheduleCompatBootstrapRetry(targetVideo, activeSource, mediaError);
      }

      clearCompatBootstrapRetry(key);
      sourceRetryAttempts[key] = nextIndex;
      sourceStallRecoveryAttempts[key] = 0;
      sourceLastRecoveryAt[key] = 0;
      const retryVariant = variants[nextIndex];

      playerWarn("retrying playback after player error", {
        activeSource,
        target: targetVideo.src,
        attempt: nextIndex,
        retryMode: retryVariant.mode,
        mediaError,
      });

      setPlayerSource(retryVariant.source, {
        reason: "error-retry",
        target: targetVideo.src,
        attempt: nextIndex,
        retryMode: retryVariant.mode,
      });
      setTimeout(() => {
        player.play().catch((error) => {
          playerErrorLog("retry play() rejected", {
            target: targetVideo.src,
            attempt: nextIndex,
            retryMode: retryVariant.mode,
            error: String(error),
          });
        });
      }, 120);

      return true;
    };

    const attemptStallRecovery = (context = {}) => {
      const activeSourceInfo = player?.currentSource?.() || null;
      const activeSource =
        activeSourceInfo?.src ||
        player?.currentSrc?.() ||
        initialVideo?.src ||
        "";
      const targetVideo = findVideoBySrc(activeSource) || initialVideo;
      if (!targetVideo?.src) return false;

      const key = targetVideo.src;
      const nowMs = Date.now();
      const lastRecoveryAt = sourceLastRecoveryAt[key] || 0;
      if (nowMs - lastRecoveryAt < PLAYER_STALL_RECOVERY_MIN_COOLDOWN_MS) {
        return false;
      }

      let attempts = sourceStallRecoveryAttempts[key] || 0;
      if (attempts >= PLAYER_STALL_RECOVERY_MAX_ATTEMPTS_PER_SOURCE) {
        playerWarn("stall recovery limit reached", {
          activeSource,
          target: key,
          attempts,
          context,
        });
        return false;
      }

      const resumeTime = player?.currentTime ? clampNumber(player.currentTime(), 0) : 0;
      const currentSource = targetVideo.preferCompat
        ? {
            src: targetVideo.compatSrc || targetVideo.src,
            type: "video/mp4",
          }
        : activeSourceInfo?.src
          ? {
              src: activeSourceInfo.src,
              type: activeSourceInfo.type || "",
            }
          : toVideoJsSource(targetVideo, targetVideo.title);
      const recoverySource = prepareRecoverySource(currentSource, key, attempts + 1);
      if (targetVideo.preferCompat && resumeTime > 0.5) {
        const transcodeStart = Math.max(0, resumeTime - 1.0);
        recoverySource.src = addQueryParam(
          recoverySource.src,
          "start",
          transcodeStart.toFixed(3)
        );
      }

      sourceStallRecoveryAttempts[key] = attempts + 1;
      sourceLastRecoveryAt[key] = nowMs;
      lastStallRecoveryAtMs = nowMs;
      clearCompatBootstrapRetry(key);

      playerWarn("stall recovery triggered", {
        activeSource,
        target: key,
        attempt: attempts + 1,
        sourceType: currentSource.type || "",
        resumeTime,
        context,
      });
      playerDebug("stall recovery source applied", {
        source: recoverySource,
      });

      let resumed = false;
      const resumePlayback = () => {
        if (resumed) return;
        resumed = true;
        if (!targetVideo.preferCompat && player?.currentTime && resumeTime > 0.2) {
          const duration = clampNumber(player.duration ? player.duration() : 0, 0);
          let seekTarget = Math.max(0, resumeTime - 0.15);
          if (duration > 0) {
            seekTarget = Math.min(seekTarget, Math.max(0, duration - 0.25));
          }
          try {
            player.currentTime(seekTarget);
          } catch (error) {
            playerWarn("stall recovery seek failed", {
              target: key,
              seekTarget,
              error: String(error),
            });
          }
        }
        player.play().catch((error) => {
          playerErrorLog("stall recovery play() rejected", {
            target: key,
            attempt: attempts + 1,
            error: String(error),
          });
        });
      };

      setPlayerSource(recoverySource, {
        reason: "stall-recovery",
        target: key,
        attempt: attempts + 1,
      });
      if (typeof player.one === "function") {
        player.one("loadedmetadata", resumePlayback);
        player.one("canplay", resumePlayback);
      }
      setTimeout(resumePlayback, 450);
      return true;
    };

    let subtitles = [];
    if (subtitleFiles.length) {
      subtitles = subtitleFiles.map((subFile) => {
        let language = "en";
        let langName = "English";

        // Try to extract language code from filename
        console.log(subFile.name);
        const langMatch = subFile.name.match(/\.([a-z]{2,3})\.(srt|vtt|sub)$/i);
        if (langMatch) {
          language = langMatch[1];
          langName = getLanguage(language);
        }

        return {
          src:
            "/api/v1/torrent/" +
            sessionId +
            "/stream/" +
            subFile.index +
            ".vtt?format=vtt",
          srclang: language,
          label: langName,
          kind: "subtitles",
          type: "vtt",
        };
      });
    }
    const initialRetryVariants = retryVariantsBySrc[initialVideo.src] || [];
    const initialSource = initialRetryVariants[0]?.source || toVideoJsSource(initialVideo, initialVideo.title);

    player = videojs(
      "video-player",
      {
        fluid: true,
        controls: true,
        autoplay: true,
        preload: "auto",
        sources: [],
        tracks: subtitles,
        html5: {
          nativeTextTracks: false
        },
        plugins: {
          hotkeys: {
            volumeStep: 0.1,
            seekStep: 5,
            enableModifiersForNumbers: false,
            enableVolumeScroll: false,
          },
        },
      },
      function () {
        player = this;
        if (activePlaybackDiagnostics) {
          activePlaybackDiagnostics.attachPlayer(player);
        }
        playerDebug("player initialized", {
          initialSource,
          trackCount: subtitles.length,
        });

        nativePlayerCurrentTime = player.currentTime.bind(player);
        nativePlayerDuration = player.duration.bind(player);
        const nativePlayerSeekable =
          typeof player.seekable === "function" ? player.seekable.bind(player) : null;

        player.currentTime = (seconds) => {
          if (!compatVirtualTimeline.enabled) {
            return typeof seconds === "number"
              ? nativePlayerCurrentTime(seconds)
              : nativePlayerCurrentTime();
          }

          if (typeof seconds !== "number") {
            return getCompatVirtualCurrentTime();
          }

          const bypassSeek = Date.now() < compatVirtualSeekBypassUntilMs;
          const nativeTargetSeconds = resolveCompatNativeSeekSeconds(seconds);
          if (bypassSeek) {
            return nativePlayerCurrentTime(nativeTargetSeconds);
          }

          if (!scheduleCompatVirtualSeek(seconds, "player.currentTime")) {
            return nativePlayerCurrentTime(nativeTargetSeconds);
          }
          return getCompatVirtualCurrentTime();
        };

        player.duration = (seconds) => {
          if (!compatVirtualTimeline.enabled) {
            return typeof seconds === "number"
              ? nativePlayerDuration(seconds)
              : nativePlayerDuration();
          }
          if (typeof seconds === "number") {
            const nextDuration = parseDurationHintSeconds(seconds);
            if (nextDuration > 0) {
              compatVirtualTimeline.durationSeconds = nextDuration;
            }
            return compatVirtualTimeline.durationSeconds;
          }
          return compatVirtualTimeline.durationSeconds || nativePlayerDuration();
        };

        player.seekable = () => {
          const virtualRange = getCompatSeekableRange();
          if (virtualRange) {
            return virtualRange;
          }
          return nativePlayerSeekable ? nativePlayerSeekable() : createSingleTimeRange(0, 0);
        };

        mediaElement = player.el()?.querySelector("video");
        ensureCompatVirtualTechPatched();
        let stallWatchdogTimerId = null;
        let stallWatchdogLastSampleAt = 0;
        let stallWatchdogLastTime = 0;
        let stallWatchdogStuckSeconds = 0;

        const resetStallWatchdog = () => {
          stallWatchdogLastSampleAt = Date.now();
          stallWatchdogLastTime = player.currentTime ? clampNumber(player.currentTime(), 0) : 0;
          stallWatchdogStuckSeconds = 0;
        };

        const stopStallWatchdog = () => {
          if (!stallWatchdogTimerId) return;
          clearInterval(stallWatchdogTimerId);
          stallWatchdogTimerId = null;
        };

        const tickStallWatchdog = () => {
          if (!mediaElement || !player) return;

          const nowMs = Date.now();
          const elapsed = stallWatchdogLastSampleAt > 0 ? (nowMs - stallWatchdogLastSampleAt) / 1000 : 0;
          const currentTime = player.currentTime ? clampNumber(player.currentTime(), 0) : 0;
          const paused = player.paused ? !!player.paused() : false;
          const ended = player.ended ? !!player.ended() : false;
          const seeking = player.seeking ? !!player.seeking() : false;
          const nativeCurrentTime = clampNumber(mediaElement.currentTime, 0);
          const readyState = clampNumber(mediaElement.readyState);
          const networkState = clampNumber(mediaElement.networkState);
          const bufferedRanges = toTimeRangesArray(mediaElement.buffered);
          const bufferAhead = getBufferAhead(bufferedRanges, currentTime);
          const activeSource =
            player.currentSource?.()?.src ||
            player.currentSrc?.() ||
            mediaElement.currentSrc ||
            "";
          const isCompatSeekBootstrap =
            activeSource.includes("/transcode/") &&
            activeSource.includes("start=") &&
            nativeCurrentTime < 0.1 &&
            readyState <= 1 &&
            networkState === 2;

          stallWatchdogLastSampleAt = nowMs;
          if (paused || ended || seeking || elapsed <= 0) {
            stallWatchdogLastTime = currentTime;
            stallWatchdogStuckSeconds = 0;
            return;
          }

          const delta = Math.abs(currentTime - stallWatchdogLastTime);
          const looksStuck = delta < 0.04 && readyState <= 2;
          if (looksStuck) {
            stallWatchdogStuckSeconds += elapsed;
          } else {
            stallWatchdogStuckSeconds = 0;
          }
          stallWatchdogLastTime = currentTime;

          const recoveryThresholdSeconds = isCompatSeekBootstrap
            ? PLAYER_STALL_RECOVERY_SEEK_BOOTSTRAP_STUCK_SECONDS
            : PLAYER_STALL_RECOVERY_STUCK_SECONDS;
          if (stallWatchdogStuckSeconds < recoveryThresholdSeconds) return;

          attemptStallRecovery({
            reason: "stuck-playhead",
            stuckSeconds: Number(stallWatchdogStuckSeconds.toFixed(3)),
            currentTime,
            bufferAhead,
            readyState,
            networkState,
            activeSource,
            recoveryThresholdSeconds,
            isCompatSeekBootstrap,
            nativeCurrentTime,
          });
          stallWatchdogStuckSeconds = 0;
        };

        if (mediaElement) {
          const mediaEvents = [
            "loadstart",
            "loadeddata",
            "canplay",
            "playing",
            "pause",
            "stalled",
            "waiting",
            "suspend",
            "abort",
            "emptied",
          ];
          mediaEvents.forEach((eventName) => {
            mediaElement.addEventListener(eventName, () => {
              playerDebug("native media event", {
                event: eventName,
                src: mediaElement.currentSrc || "",
                currentTime: mediaElement.currentTime,
                readyState: mediaElement.readyState,
                networkState: mediaElement.networkState,
              });
            });
          });
          mediaElement.addEventListener("error", () => {
            const nativeError = mediaElement.error;
            playerErrorLog("native media error", {
              src: mediaElement.currentSrc || "",
              code: nativeError?.code || 0,
              codeText: mediaErrorCodeText(nativeError?.code || 0),
              message: nativeError?.message || "",
              readyState: mediaElement.readyState,
              networkState: mediaElement.networkState,
            });
          });
        } else {
          playerWarn("native media element was not found");
        }
        stallWatchdogTimerId = setInterval(tickStallWatchdog, PLAYER_STALL_RECOVERY_TICK_MS);
        resetStallWatchdog();
        player.on("dispose", () => {
          stopStallWatchdog();
          disableCompatVirtualTimeline("dispose");
          Object.keys(sourceCompatBootstrapRetryTimers).forEach((key) => {
            clearCompatBootstrapRetry(key);
          });
        });

        player.on("loadstart", () => {
          ensureCompatVirtualTechPatched();
          updateCompatVirtualTimelineForSource(player.currentSrc(), "loadstart");
          freezeCompatVirtualClock();
        });
        player.on("loadedmetadata", () => {
          ensureCompatVirtualTechPatched();
          updateCompatVirtualTimelineForSource(player.currentSrc(), "loadedmetadata");
          const currentVideo = findVideoBySrc(player.currentSrc());
          if (currentVideo?.src) {
            sourceRetryAttempts[currentVideo.src] = 0;
            sourceStallRecoveryAttempts[currentVideo.src] = 0;
            sourceLastRecoveryAt[currentVideo.src] = 0;
            sourceCompatBootstrapRetryAttempts[currentVideo.src] = 0;
            clearCompatBootstrapRetry(currentVideo.src);
          }
          resetStallWatchdog();
          playerDebug("loadedmetadata", {
            src: player.currentSrc(),
            duration: player.duration(),
            videoWidth: player.videoWidth(),
            videoHeight: player.videoHeight(),
          });
        });
        player.on("stalled", () => {
          freezeCompatVirtualClock();
          playerWarn("stalled", { src: player.currentSrc() });
        });
        player.on("waiting", () => {
          freezeCompatVirtualClock();
          playerWarn("waiting", { src: player.currentSrc() });
        });
        player.on("pause", () => {
          freezeCompatVirtualClock();
        });
        player.on("ended", () => {
          if (!compatVirtualTimeline.enabled) return;
          const endTime =
            compatVirtualTimeline.durationSeconds > 0
              ? compatVirtualTimeline.durationSeconds
              : getCompatVirtualCurrentTime();
          setCompatVirtualBase(endTime, false);
        });
        player.on("playing", () => {
          updateCompatVirtualTimelineForSource(player.currentSrc(), "playing");
          resumeCompatVirtualClock();
          resetStallWatchdog();
          const currentVideo = findVideoBySrc(player.currentSrc());
          if (currentVideo?.src) {
            sourceStallRecoveryAttempts[currentVideo.src] = 0;
            sourceLastRecoveryAt[currentVideo.src] = 0;
            sourceCompatBootstrapRetryAttempts[currentVideo.src] = 0;
            clearCompatBootstrapRetry(currentVideo.src, true);
          }
          lastStallRecoveryAtMs = 0;
        });
        player.on("seeking", () => {
          freezeCompatVirtualClock();
          resetStallWatchdog();
        });
        player.on("error", () => {
          freezeCompatVirtualClock();
          const mediaError = player.error ? player.error() : null;
          const activeSource =
            player.currentSource()?.src ||
            player.currentSrc() ||
            videoUrls[0]?.src ||
            "";
          const normalizedMediaError = mediaError
            ? {
                code: mediaError.code || 0,
                codeText: mediaErrorCodeText(mediaError.code || 0),
                message: mediaError.message || "",
              }
            : null;
          const activeVideo = findVideoBySrc(activeSource) || initialVideo;
          const isRecoverySource = activeSource.includes("_bp_recover=");
          const isRecentRecoveryError = Date.now() - lastStallRecoveryAtMs < 9000;
          playerErrorLog("error event", {
            activeSource,
            mediaError: normalizedMediaError,
            currentTime: player.currentTime ? player.currentTime() : null,
            readyState: player.readyState ? player.readyState() : null,
            networkState: player.networkState ? player.networkState() : null,
            sources: videoUrls.map((video) => ({
              title: video.title,
              src: video.src,
              type: video.type || "",
            })),
            latestSourceDiagnostics,
          });

          if (isRecoverySource || isRecentRecoveryError) {
            playerWarn("suppressing error toast during stall recovery", {
              activeSource,
              isRecoverySource,
              isRecentRecoveryError,
              mediaError: normalizedMediaError,
            });
            if (scheduleCompatBootstrapRetry(activeVideo, activeSource, normalizedMediaError)) {
              clearPlayerErrorState("recovery-source");
              return;
            }
            clearPlayerErrorState("recovery-source");
            return;
          }

          if (retryPlaybackAfterError(activeSource, normalizedMediaError)) {
            clearPlayerErrorState("error-retry");
            return;
          }
          if (scheduleCompatBootstrapRetry(activeVideo, activeSource, normalizedMediaError)) {
            clearPlayerErrorState("compat-bootstrap-retry");
            return;
          }

          butterup.toast({
            message: "No compatible source found for this media",
            location: "top-right",
            icon: true,
            dismissable: true,
            type: "error",
          });
        });

        if (!initialSource.src) {
          playerErrorLog("initial source is empty", {
            initialVideo,
          });
          return;
        }

        playerDebug("applying initial source", {
          source: initialSource,
        });
        if (initialVideo?.src) {
          sourceRetryAttempts[initialVideo.src] = 0;
          sourceStallRecoveryAttempts[initialVideo.src] = 0;
          sourceLastRecoveryAt[initialVideo.src] = 0;
          sourceCompatBootstrapRetryAttempts[initialVideo.src] = 0;
          clearCompatBootstrapRetry(initialVideo.src);
        }
        setPlayerSource(initialSource, {
          reason: "initial-source",
        });
        player.play().catch((error) => {
          playerErrorLog("initial play() rejected", {
            src: initialSource.src,
            error: String(error),
          });
        });
      }
    );
    player.doubleTapFF();

    document.querySelector("#video-player").style.display = "block";
    // scroll to video player
    setTimeout(() => {
      window.scrollTo({
        top: document.body.scrollHeight,
        behavior: "smooth",
      });

      if (videoUrls.length > 1) {
        const videoSelect = document.createElement("select");
        videoSelect.setAttribute("id", "video-select");
        videoSelect.setAttribute("class", "video-select");
        videoSelect.setAttribute("aria-label", "Select video");
        videoUrls.forEach((video) => {
          const option = document.createElement("option");
          option.setAttribute("value", video.src);
          option.innerHTML = video.title;
          videoSelect.appendChild(option);
        });
        videoSelect.addEventListener("change", (e) => {
          const selectedSrc = e.target.value;
          const selectedVideo = videoUrls.find((video) => video.src === selectedSrc);
          if (selectedVideo?.src) {
            sourceRetryAttempts[selectedVideo.src] = 0;
            sourceStallRecoveryAttempts[selectedVideo.src] = 0;
            sourceLastRecoveryAt[selectedVideo.src] = 0;
            sourceCompatBootstrapRetryAttempts[selectedVideo.src] = 0;
            clearCompatBootstrapRetry(selectedVideo.src);
          }
          playerDebug("manual source change", {
            selectedSrc,
            type: selectedVideo?.type || "",
          });
          probeSelectedVideo(selectedVideo, "manual").then((diagnostics) => {
            updateVideoDurationHintFromDiagnostics(
              selectedVideo,
              diagnostics,
              "manual"
            );
            latestSourceDiagnostics = {
              ...latestSourceDiagnostics,
              manualDiagnostics: diagnostics,
            };
            if (activePlaybackDiagnostics) {
              activePlaybackDiagnostics.setSourceDiagnostics(latestSourceDiagnostics);
            }
            playerDebug("manual source diagnostics", diagnostics);
          });
          if (!selectedVideo?.src) {
            playerErrorLog("manual source is empty", { selectedVideo });
            return;
          }
          const selectedVariants = retryVariantsBySrc[selectedVideo.src] || [];
          const selectedSource = selectedVariants[0]?.source || toVideoJsSource(selectedVideo, selectedVideo?.title || "");
          setPlayerSource(selectedSource, {
            reason: "manual-source-change",
            selectedSrc: selectedVideo.src,
          });
          player.play().catch((error) => {
            playerErrorLog("manual play() rejected", {
              selectedSrc: selectedVideo.src,
              error: String(error),
            });
          });
        });
        document.querySelector("#video-player").appendChild(videoSelect);
      }
    }, 300);

    form.querySelector("button[type=submit]").removeAttribute("disabled");
    form.querySelector("button[type=submit]").innerHTML = "Play Now";
    form.querySelector("button[type=submit]").classList.remove("loader");
    document.querySelectorAll("#play-torrent").forEach((el) => {
      el.removeAttribute("disabled");
      el.innerHTML = "Watch";
      el.classList.remove("loader");
    });
    loadSavedTorrents();
  });

  // create switch button
  const switchInputs = document.querySelectorAll("#switchInput");
  switchInputs.forEach((input) => {
    input.querySelector("input").addEventListener("change", (e) => {
      const dot = e.target.parentElement.querySelector(".dot");
      const wrapper = e.target.parentElement.querySelector(".switch-wrapper");
      if (e.target.checked) {
        dot.classList.add("translate-x-full", "!bg-muted");
        wrapper.classList.add("bg-primary");
      } else {
        dot.classList.remove("translate-x-full", "!bg-muted");
        wrapper.classList.remove("bg-primary");
      }
    });
  });

  document.querySelector("#settings-btn").addEventListener("click", () => {
    document.querySelector("#settings-model").classList.toggle("hidden");
  });

  document.querySelectorAll("#close-settings").forEach((el) => {
    el.addEventListener("click", () => {
      document.querySelector("#settings-model").classList.toggle("hidden");
      document.querySelector("#proxy-result").classList.remove("flex");
    document.querySelector("#proxy-result").classList.add("hidden");
    });
  });

  document.querySelectorAll(".tab-btn").forEach((el) => {
    el.addEventListener("click", () => {
      const tabIndex = el.getAttribute("data-index");
      document.querySelectorAll(".tab").forEach((tab) => {
        const index = tab.getAttribute("data-tab");
        if (index === tabIndex) {
          tab.classList.remove("hidden");
          document.querySelectorAll(".tab-btn").forEach((el) => {
            el.classList.remove("bg-primary", "text-primary-foreground");
            el.classList.add("bg-muted");
          });
          el.classList.add("bg-primary", "text-primary-foreground");
        } else {
          tab.classList.add("hidden");
        }
      });
    });
  });

  function generatePagination(currentPage, pageSize, total, target) {
    const pagination = document.querySelector(target);
    if (!pagination) return;
    pagination.classList.remove("hidden");
    pagination.innerHTML = "";
    const totalPages = Math.ceil(total / pageSize);
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);

    for (let i = startPage; i <= endPage; i++) {
      const pageButton = document.createElement("button");
      pageButton.textContent = i;
      pageButton.classList.add("page-button");
      if (i === currentPage) {
        pageButton.classList.add("active");
      }
      pageButton.addEventListener("click", () => {
        searchPage = i;
        updateSearchResults();
      });
      pagination.appendChild(pageButton);
    }
    const prevButton = document.createElement("button");
    prevButton.innerHTML = `<svg stroke="currentColor" fill="currentColor" stroke-width="0" viewBox="0 0 20 20" aria-hidden="true" height="1em" width="1em" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M4.72 9.47a.75.75 0 0 0 0 1.06l4.25 4.25a.75.75 0 1 0 1.06-1.06L6.31 10l3.72-3.72a.75.75 0 1 0-1.06-1.06L4.72 9.47Zm9.25-4.25L9.72 9.47a.75.75 0 0 0 0 1.06l4.25 4.25a.75.75 0 1 0 1.06-1.06L11.31 10l3.72-3.72a.75.75 0 0 0-1.06-1.06Z" clip-rule="evenodd"></path></svg>`;
    prevButton.classList.add("page-button");
    prevButton.disabled = currentPage === 1;
    prevButton.addEventListener("click", () => {
      if (currentPage > 1) {
        searchPage--;
        updateSearchResults();
      }
    });
    pagination.prepend(prevButton);
    const nextButton = document.createElement("button");
    nextButton.innerHTML = `<svg stroke="currentColor" fill="currentColor" stroke-width="0" viewBox="0 0 20 20" aria-hidden="true" height="1em" width="1em" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M15.28 9.47a.75.75 0 0 1 0 1.06l-4.25 4.25a.75.75 0 1 1-1.06-1.06L13.69 10 9.97 6.28a.75.75 0 0 1 1.06-1.06l4.25 4.25ZM6.03 5.22l4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.75.75 0 0 1-1.06-1.06L8.69 10 4.97 6.28a.75.75 0 0 1 1.06-1.06Z" clip-rule="evenodd"></path></svg>`;
    nextButton.classList.add("page-button");
    nextButton.disabled = currentPage === totalPages;
    nextButton.addEventListener("click", () => {
      if (currentPage < totalPages) {
        searchPage++;
        updateSearchResults();
      }
    });
    pagination.appendChild(nextButton);
  }

  let searchData = [];
  let searchPage = 1;
  let searchPageSize = 5;

  const updateSearchResults = () => {
    const searchPagination = document.querySelector("#search-pagination");
    const searchResults = document.querySelector("#search-result");
    searchResults.classList.remove("hidden");
    searchResults.querySelector("tbody").innerHTML = "";
    searchResults.querySelector("tfoot").classList.add("hidden");
    if (searchData.length === 0) {
      searchResults.querySelector("tfoot").classList.remove("hidden");
      return;
    }

    const start = (searchPage - 1) * searchPageSize;
    const end = start + searchPageSize;
    const results = searchData.slice(start, end);
    results.forEach((result) => {
      const resultDiv = document.createElement("tr");
      resultDiv.innerHTML = `
        <td>${result.title}</td>
        <td>${result.indexer}</td>
        <td>${result.size}</td>
        <td>${result.leechers}/${result.seeders}</td>
        <td><button id="play-torrent" type="button" class="btn small" data-magnet="${
          result.downloadUrl || result.magnetUrl
        }">Watch</button></td>
      `;
      searchResults.querySelector("tbody").appendChild(resultDiv);
    });

    // Generate pagination
    const totalResults = searchData.length;
    const totalPages = Math.ceil(totalResults / searchPageSize);
    generatePagination(
      searchPage,
      searchPageSize,
      totalResults,
      "#search-pagination"
    );

    // Add event listener to each play button
    searchResults.querySelectorAll("#play-torrent").forEach((el) => {
      el.addEventListener("click", async (e) => {
        const magnet = e.target.getAttribute("data-magnet");
        document.querySelector("#magnet").value = magnet;
        document
          .querySelector("#torrent-form")
          .dispatchEvent(new Event("submit"));
        e.target.setAttribute("disabled", "disabled");
        e.target.innerHTML = "";
        e.target.classList.add("loader");
      });
    });
  };

  document.querySelector("#search-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const query = e.target.querySelector("#search").value;
    if (!query) {
      butterup.toast({
        message: "Please enter a search query",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      return;
    }

    searchData = [];
    searchPage = 1;

    e.target
      .querySelector("button[type=submit]")
      .setAttribute("disabled", "disabled");
    e.target.querySelector("button[type=submit]").classList.add("loader");
    e.target.querySelector("button[type=submit]").innerHTML = "";
    const searchResults = document.querySelector("#search-result");

    searchResults.classList.add("hidden");
    document.querySelector("#search-pagination").classList.add("hidden");

    let apiUrl = "/api/v1/prowlarr/search";

    if (
      (!settings.prowlarrHost || !settings.prowlarrApiKey) &&
      settings.jackettHost &&
      settings.jackettApiKey
    ) {
      apiUrl = "/api/v1/jackett/search";
    }

    fetch(`${apiUrl}?q=${query}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    })
      .then(async (res) => {
        if (!res.ok) {
          const err = await res.json();
          throw new Error(res.error || "Failed to fetch search results");
        }
        return res.json();
      })
      .then((data) => {
        if (data && typeof data === "object") {
          searchData = data;
        } else {
          searchData = [];
        }

        updateSearchResults();
      })
      .catch((error) => {
        console.error("There was a problem with the fetch operation:", error);
        butterup.toast({
          message: error.message || "Failed to fetch search results",
          location: "top-right",
          icon: true,
          dismissable: true,
          type: "error",
        });
      })
      .finally(() => {
        e.target
          .querySelector("button[type=submit]")
          .removeAttribute("disabled");
        e.target
          .querySelector("button[type=submit]")
          .classList.remove("loader");
        e.target.querySelector("button[type=submit]").innerHTML = "Search";
      });
  });

  const testProwlarrConfig = async () => {
    const prowlarrHost = document.querySelector("#prowlarrHost").value;
    const prowlarrApiKey = document.querySelector("#prowlarrApiKey").value;
    const prowlarrTestBtn = document.querySelector("#test-prowlarr");

    if (!prowlarrHost || !prowlarrApiKey) {
      butterup.toast({
        message: "Please enter Prowlarr host and API key",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      return false;
    }

    prowlarrTestBtn.setAttribute("disabled", "disabled");
    prowlarrTestBtn.querySelector("span").innerHTML = "Testing...";
    
    const response = await fetch("/api/v1/prowlarr/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prowlarrHost, prowlarrApiKey }),
    });

    const data = await response.json();
    if (!response.ok) {
      butterup.toast({
        message: data.error || "Failed to test Prowlarr connection",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      prowlarrTestBtn.removeAttribute("disabled");
      prowlarrTestBtn.querySelector("span").innerHTML = "Test Connection";
      return false;
    }

    butterup.toast({
      message: "Prowlarr settings are valid",
      location: "top-right",
      icon: true,
      dismissable: true,
      type: "success",
    });

    prowlarrTestBtn.removeAttribute("disabled");
    prowlarrTestBtn.querySelector("span").innerHTML = "Test Connection";

    return true;
  }

  document.querySelector("#test-prowlarr").addEventListener("click", (e) => {
    testProwlarrConfig();
  });

  const testJackettConfig = async () => {
    const jackettHost = document.querySelector("#jackettHost").value;
    const jackettApiKey = document.querySelector("#jackettApiKey").value;
    const jackettTestBtn = document.querySelector("#test-jackett");

    if (!jackettHost || !jackettApiKey) {
      butterup.toast({
        message: "Please enter Jackett host and API key",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      return false;
    }

    jackettTestBtn.setAttribute("disabled", "disabled");
    jackettTestBtn.querySelector("span").innerHTML = "Testing...";
    
    const response = await fetch("/api/v1/jackett/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jackettHost, jackettApiKey }),
    });

    const data = await response.json();
    if (!response.ok) {
      butterup.toast({
        message: data.error || "Failed to test Jackett connection",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      jackettTestBtn.removeAttribute("disabled");
      jackettTestBtn.querySelector("span").innerHTML = "Test Connection";
      return false;
    }

    butterup.toast({
      message: "Jackett settings are valid",
      location: "top-right",
      icon: true,
      dismissable: true,
      type: "success",
    });

    jackettTestBtn.removeAttribute("disabled");
    jackettTestBtn.querySelector("span").innerHTML = "Test Connection";

    return true;
  }

  document.querySelector("#test-jackett").addEventListener("click", (e) => {
    testJackettConfig();
  });

  const testProxy = async () => {
    const proxyUrl = document.querySelector("#proxyUrl").value;
    const proxyBtn = document.querySelector("#test-proxy");

    if (!proxyUrl) {
      butterup.toast({
        message: "Please enter a proxy URL",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      return false;
    }

    proxyBtn.setAttribute("disabled", "disabled");
    proxyBtn.querySelector("span").innerHTML = "Testing...";

    const response = await fetch("/api/v1/proxy/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proxyUrl }),
    });

    const data = await response.json();

    if (!response.ok) {
      butterup.toast({
        message: data.error || "Failed to test Proxy connection",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
      proxyBtn.removeAttribute("disabled");
      proxyBtn.querySelector("span").innerHTML = "Test Proxy";
      return false;
    }

    butterup.toast({
      message: "Proxy url is valid",
      location: "top-right",
      icon: true,
      dismissable: true,
      type: "success",
    });

    proxyBtn.removeAttribute("disabled");
    proxyBtn.querySelector("span").innerHTML = "Test Proxy";

    if (data?.origin) {
      document.querySelector("#proxy-result").classList.remove("hidden");
      document.querySelector("#proxy-result").classList.add("flex");
      document.querySelector("#proxy-result .output-ip").innerHTML = data?.origin
    }

    return true;
  }

  document.querySelector("#test-proxy").addEventListener("click", () => {
    testProxy();
  });

  document
    .querySelector("#proxy-settings-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const enableProxy = e.target.querySelector("#enableProxy").checked;
      const proxyUrl = e.target.querySelector("#proxyUrl").value;
      const submitButton = e.target.querySelector("button[type=submit]");

      submitButton.setAttribute("disabled", "disabled");

      if (enableProxy) {
        const isValid = await testProxy();
        if (!isValid) {
          submitButton.removeAttribute("disabled");
          return;
        }
      }

      submitButton.classList.add("loader");
      submitButton.innerHTML = "Saving...";

      const body = {
        enableProxy,
        proxyUrl,
      };

      const response = await fetch("/api/v1/settings/proxy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })

      const data = await response.json();

      if (!response.ok) {
        butterup.toast({
          message: data.error || "Failed to save settings",
          location: "top-right",
          icon: true,
          dismissable: true,
          type: "error",
        });
      } else {
        butterup.toast({
          message: "Proxy settings saved successfully",
          location: "top-right",
          icon: true,
          dismissable: true,
          type: "success",
        });

        settings = {
          ...settings,
          enableProxy: body.enableProxy,
          proxyUrl: body.proxyUrl,
        };
      }

      submitButton.removeAttribute("disabled");
      submitButton.classList.remove("loader");
      submitButton.innerHTML = "Save Settings";
    });

  document
    .querySelector("#prowlarr-settings-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const enableProwlarr = e.target.querySelector("#enableProwlarr").checked;
      const prowlarrHost = e.target.querySelector("#prowlarrHost").value;
      const prowlarrApiKey = e.target.querySelector("#prowlarrApiKey").value;
      const submitButton = e.target.querySelector("button[type=submit]");

      submitButton.setAttribute("disabled", "disabled");

      if (enableProwlarr) {
        const isValid = await testProwlarrConfig();
        if (!isValid) {
          submitButton.removeAttribute("disabled");
          return;
        }
      }

      submitButton.classList.add("loader");
      submitButton.innerHTML = "Saving...";

      const body = {
        enableProwlarr,
        prowlarrHost,
        prowlarrApiKey,
      };

      const response = await fetch("/api/v1/settings/prowlarr", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })

      const data = await response.json();
      if (!response.ok) {
        butterup.toast({
          message: data.error || "Failed to save settings",
          location: "top-right",
          icon: true,
          dismissable: true,
          type: "error",
        });
      } else {
        butterup.toast({
          message: "Prowlarr settings saved successfully",
          location: "top-right",
          icon: true,
          dismissable: true,
          type: "success",
        });

        settings = {
          ...settings,
          enableProwlarr: body.enableProwlarr,
          prowlarrHost: body.prowlarrHost,
          prowlarrApiKey: body.prowlarrApiKey,
        };

        // Check if Prowlarr or Jackett is enabled
        if (body?.enableProwlarr || settings?.enableJackett) {
          searchWrapper.classList.remove("hidden");
        } else {
          searchWrapper.classList.add("hidden");
        }
      }

      submitButton.removeAttribute("disabled");
      submitButton.classList.remove("loader");
      submitButton.innerHTML = "Save Settings";
    });

  document
  .querySelector("#jackett-settings-form")
  .addEventListener("submit", async (e) => {
    e.preventDefault();
    const enableJackett = e.target.querySelector("#enableJackett").checked;
    const jackettHost = e.target.querySelector("#jackettHost").value;
    const jackettApiKey = e.target.querySelector("#jackettApiKey").value;
    const submitButton = e.target.querySelector("button[type=submit]");

    submitButton.setAttribute("disabled", "disabled");

    if (enableJackett) {
      const isValid = await testJackettConfig();
      if (!isValid) {
        submitButton.removeAttribute("disabled");
        return;
      }
    }

    submitButton.classList.add("loader");
    submitButton.innerHTML = "Saving...";

    const body = {
      enableJackett,
      jackettHost,
      jackettApiKey,
    };

    const response = await fetch("/api/v1/settings/jackett", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })

    const data = await response.json();
    if (!response.ok) {
      butterup.toast({
        message: data.error || "Failed to save settings",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "error",
      });
    } else {
      butterup.toast({
        message: "Jackett settings saved successfully",
        location: "top-right",
        icon: true,
        dismissable: true,
        type: "success",
      });

      settings = {
        ...settings,
        enableJackett: body.enableJackett,
        jackettHost: body.jackettHost,
        jackettApiKey: body.jackettApiKey,
      };

      // Check if Jackett or Jackett is enabled
      if (body?.enableJackett || settings?.enableJackett) {
        searchWrapper.classList.remove("hidden");
      } else {
        searchWrapper.classList.add("hidden");
      }
    }

    submitButton.removeAttribute("disabled");
    submitButton.classList.remove("loader");
    submitButton.innerHTML = "Save Settings";
  });

  document.querySelector("#torrent_file").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) {
      const formData = new FormData();
      formData.append("torrent", file);

      fetch("/api/v1/torrent/convert", {
        method: "POST",
        body: formData,
      })
        .then(async (res) => {
          if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || "Failed to upload torrent file");
          }
          return res.json();
        })
        .then((data) => {
          document.querySelector("#magnet").value = data.magnet;
          document
            .querySelector("#torrent-form")
            .dispatchEvent(new Event("submit"));
        })
        .catch((error) => {
          console.error("There was a problem with the fetch operation:", error);
          butterup.toast({
            message: error.message || "Failed to upload torrent file",
            location: "top-right",
            icon: true,
            dismissable: true,
            type: "error",
          });
        });
    }
  });

  const torrentFileWrapper = document.querySelector("#torrent_file_wrapper");
  torrentFileWrapper.addEventListener("dragenter", (e) => {
    e.preventDefault();
    e.stopPropagation();
    torrentFileWrapper.classList.add("drag-over");
  });
  torrentFileWrapper.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.stopPropagation();
  });
  torrentFileWrapper.addEventListener("dragleave", (e) => {
    e.preventDefault();
    e.stopPropagation();
    torrentFileWrapper.classList.remove("drag-over");
  });
  torrentFileWrapper.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    torrentFileWrapper.classList.remove("drag-over");
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      if (file.name.endsWith(".torrent")) {
        const formData = new FormData();
        formData.append("torrent", file);

        fetch("/api/v1/torrent/convert", {
          method: "POST",
          body: formData,
        })
          .then(async (res) => {
            if (!res.ok) {
              const err = await res.json();
              throw new Error(err.error || "Failed to upload torrent file");
            }
            return res.json();
          })
          .then((data) => {
            document.querySelector("#magnet").value = data.magnet;
            document
              .querySelector("#torrent-form")
              .dispatchEvent(new Event("submit"));
          })
          .catch((error) => {
            console.error(
              "There was a problem with the fetch operation:",
              error
            );
            butterup.toast({
              message: error.message || "Failed to upload torrent file",
              location: "top-right",
              icon: true,
              dismissable: true,
              type: "error",
            });
          });
      } else {
        butterup.toast({
          message: "Please drop a valid torrent file",
          location: "top-right",
          icon: true,
          dismissable: true,
          type: "error",
        });
      }
    }
  });

  loadSavedTorrents();

  // fetch settings
  fetch("/api/v1/settings")
    .then((res) => {
      if (!res.ok) {
        throw new Error("Network response was not ok");
      }
      return res.json();
    })
    .then((data) => {
      settings = data;
      document.querySelector("#enableProxy").checked = data.enableProxy;
      document.querySelector("#proxyUrl").value = data.proxyUrl || "";
      document.querySelector("#enableProwlarr").checked =
        data.enableProwlarr || false;
      document.querySelector("#prowlarrHost").value = data.prowlarrHost || "";
      document.querySelector("#prowlarrApiKey").value =
        data.prowlarrApiKey || "";
      document.querySelector("#enableJackett").checked =
        data.enableJackett || false;
      document.querySelector("#jackettHost").value = data.jackettHost || "";
      document.querySelector("#jackettApiKey").value = data.jackettApiKey || "";

      // Set switch button state
      const switchInputs = document.querySelectorAll("#switchInput");
      switchInputs.forEach((input) => {
        const dot = input.querySelector(".dot");
        const wrapper = input.querySelector(".switch-wrapper");
        if (input.querySelector("input").checked) {
          dot.classList.add("translate-x-full", "!bg-muted");
          wrapper.classList.add("bg-primary");
        } else {
          dot.classList.remove("translate-x-full", "!bg-muted");
          wrapper.classList.remove("bg-primary");
        }
      });

      // Check if Prowlarr or Jackett is enabled
      if (data?.enableProwlarr || data?.enableJackett) {
        searchWrapper.classList.remove("hidden");
      } else {
        searchWrapper.classList.add("hidden");
      }
    })
    .catch((error) => {
      console.error("There was a problem with the fetch operation:", error);
    });
})();
