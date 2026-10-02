#!/usr/bin/env python3
# FortiGate → cno.* bridge. Reads the latest value of every fortigate.* series the Network
# Insights app needs from Grail, re-emits it as the matching cno.* metric. The FortiGate
# extension keeps running untouched; this script is purely translation.
#
# WHY A BRIDGE AND NOT A SECOND EXTENSION: the FortiGate extension already polls these devices
# at 1/min; adding a second SNMP poll doubles traffic to each firewall for data that is already
# in Grail. Reading from Grail is one query per metric, no device impact.
#
# RUN LOCALLY: `python3 scripts/fortigate_bridge.py` (uses current dtctl context for reads;
# needs DT_URL + DT_TOKEN env vars for the ingest side). PROMOTE TO WORKFLOW: port the two
# HTTP helpers to the workflow runtime's `dt-sdk` client.
#
# TIMESTAMPS: ingest uses the ORIGINAL point's timestamp from Grail so re-runs are idempotent.
# fortigate.* and cno.* are different series, so there is no collision risk.

import json, os, ssl, subprocess, sys, time, urllib.request

DT_URL   = os.environ.get("DT_URL", "").rstrip("/")
DT_TOKEN = os.environ.get("DT_TOKEN", "")
CONTEXT  = os.environ.get("DTCTL_CONTEXT", "")
if not DT_URL:   raise SystemExit("DT_URL env var required (e.g. https://abc12345.apps.dynatrace.com)")
if not CONTEXT:  raise SystemExit("DTCTL_CONTEXT env var required (name of the dtctl context used for reads)")
WINDOW   = os.environ.get("BRIDGE_WINDOW", "5m")   # how far back to look for the latest point
DRY_RUN  = "--dry-run" in sys.argv

# Classic /api/v2/metrics/ingest lives on the live.dynatrace.com host, not apps.dynatrace.com.
# dt0c01.* tokens are classic API tokens and only work against the classic endpoint. Derive
# the ingest base from DT_URL unless overridden explicitly.
INGEST_URL = os.environ.get("INGEST_URL") or \
    DT_URL.replace(".apps.dynatrace.com", ".live.dynatrace.com")

# Python installed from python.org on macOS ships without a usable CA bundle; fall back to the
# system bundle so urllib doesn't fail with "unable to get local issuer certificate".
_SSL_CTX = ssl.create_default_context(cafile="/etc/ssl/cert.pem") \
    if os.path.exists("/etc/ssl/cert.pem") else ssl.create_default_context()

# Each entry: a DQL query returning one row per series with the dims we need, plus the metric
# key + value expression we emit on the cno.* side. The query is written as `timeseries
# val=last(X), by:{...}` so a single empty series does not drop the others (CLAUDE.md Rule 1 —
# never multi-aggregate; one metric per query, no append needed).
#
# emit() takes a record and returns a (metric_key, dims-dict, value, timestamp_ms) tuple or
# None to skip that record.

def _ifdims(r):
    return {
        "device.address": r["device.address"],
        "sys_name":       r.get("sys.name", r["device.address"]),
        "if_index":       r["if.id"],
        "if_descr":       r.get("if.name", r["if.id"]),
        "source":         "fortigate-bridge",
    }

def _devdims(r):
    return {
        "device.address": r["device.address"],
        "sys_name":       r.get("sys.name", r["device.address"]),
        "source":         "fortigate-bridge",
    }

# FortiGate oper_status is 1=up / 0=down. The contract requires 1=up / 2=down (snmp-style).
def _oper(v):  return 1 if v == 1 else 2

# DQL has no `last()` aggregator. For gauges we use avg(); for counters, sum(). Over a 1-min
# bucket both reduce to the value the FortiGate extension wrote. latest_point() then walks the
# array back to the newest non-null bucket.
_IFBY = "by:{device.address, sys.name, `if.id`, `if.name`}"
_DVBY = "by:{device.address, sys.name}"
_FROM = f"from:now()-{WINDOW}, interval:1m"

MAPPINGS = [
    # cno.if.oper_status — satisfies the roster tier even without cno.device.uptime.
    { "query": f"timeseries val=avg(fortigate.interface.status), {_IFBY}, {_FROM}",
      "key":   "cno.if.oper_status", "dims": _ifdims,
      "value": lambda v: _oper(int(round(v))) },

    { "query": f"timeseries val=sum(fortigate.interface.bytes.in.count), {_IFBY}, {_FROM}",
      "key":   "cno.if.in_octets.count", "dims": _ifdims, "value": lambda v: v },

    { "query": f"timeseries val=sum(fortigate.interface.bytes.out.count), {_IFBY}, {_FROM}",
      "key":   "cno.if.out_octets.count", "dims": _ifdims, "value": lambda v: v },

    { "query": f"timeseries val=sum(fortigate.interface.errors.in.count), {_IFBY}, {_FROM}",
      "key":   "cno.if.in_errors.count", "dims": _ifdims, "value": lambda v: v },

    { "query": f"timeseries val=sum(fortigate.interface.errors.out.count), {_IFBY}, {_FROM}",
      "key":   "cno.if.out_errors.count", "dims": _ifdims, "value": lambda v: v },

    # Speed lives on the if.speed DIMENSION, not the metric value. Pull series metadata (which
    # is cheap — no datapoint scan) and re-emit if.speed as the metric value.
    { "query": f"fetch metric.series, from:now()-{WINDOW} "
               f"| filter metric.key == \"fortigate.interface.speed\" "
               f"| fields device.address, `sys.name`, `if.id`, `if.name`, `if.speed`",
      "key":   "cno.if.high_speed", "dims": _ifdims,
      "value": lambda r: int(r.get("if.speed") or 0),
      "value_from_record": True },

    { "query": f"timeseries val=avg(fortigate.cpu.usage), {_DVBY}, {_FROM}",
      "key":   "cno.device.cpu_usage", "dims": _devdims, "value": lambda v: v },
]


def dqlquery(q):
    # Reuse the user's existing dtctl session rather than wiring up a second auth path. The
    # downside is the script needs dtctl on PATH; the upside is zero config for a read scope
    # that is already granted. `--max-result-records` is bumped so the 1k default limit does
    # not quietly drop devices on large fleets.
    out = subprocess.check_output(
        ["dtctl", "query", q, "-o", "json", "--context", CONTEXT,
         "--max-result-records", "20000"],
        stderr=subprocess.STDOUT)
    text = out.decode()
    # dtctl emits advisory lines ("Warning: Your result has been limited to…") to stdout
    # BEFORE the JSON. json.loads chokes on the whole blob; find the start of the object.
    start = text.find("{")
    if start < 0:
        raise RuntimeError(f"no JSON in dtctl output: {text[:200]}")
    env = json.loads(text[start:])
    if "error" in env and env.get("ok") is False:
        raise RuntimeError(f"dtctl error: {env['error']}")
    return env.get("records", [])


def latest_point(ts_array, timeframe):
    # timeseries returns parallel arrays. Walk back to the newest non-null bucket so a
    # momentarily-empty tail does not read as "no data". (CLAUDE.md Rule 2.)
    if not ts_array:
        return None, None
    for i in range(len(ts_array) - 1, -1, -1):
        if ts_array[i] is not None:
            # Compute the bucket's end timestamp. timeframe comes back as ISO strings.
            start_ns = int(_isots(timeframe["start"]))
            end_ns   = int(_isots(timeframe["end"]))
            step = (end_ns - start_ns) // len(ts_array)
            bucket_end = start_ns + step * (i + 1)
            return ts_array[i], bucket_end // 1_000_000   # → ms
    return None, None


def _isots(s):
    # 2026-10-02T16:43:00.000000000Z → epoch ns, no deps.
    import datetime
    s = s.replace("Z", "+00:00")
    # strip > 6 fractional digits (Python chokes on nanoseconds)
    if "." in s:
        head, tail = s.split(".")
        frac, tz = tail[:-6], tail[-6:]
        s = f"{head}.{frac[:6]}{tz}"
    dt = datetime.datetime.fromisoformat(s)
    return int(dt.timestamp() * 1_000_000_000)


def line(key, dims, value, ts_ms):
    # Line protocol: metric_key,d1=v1,d2=v2 value [timestamp_ms]
    # Values with commas/spaces/= must be quoted or escaped. FortiGate interface names can
    # include "/" and spaces (e.g. "WLAN DATA"); escape spaces/commas/= per the spec.
    def esc(s):
        return str(s).replace("\\", "\\\\").replace(",", "\\,").replace(" ", "\\ ").replace("=", "\\=")
    dim_str = ",".join(f"{k}={esc(v)}" for k, v in dims.items() if v not in (None, ""))
    return f"{key},{dim_str} {value} {ts_ms}"


def ingest(lines):
    if not DT_TOKEN:
        raise SystemExit("DT_TOKEN env var required (needs metrics.ingest scope)")
    body = ("\n".join(lines) + "\n").encode()
    req = urllib.request.Request(
        f"{INGEST_URL}/api/v2/metrics/ingest", data=body,
        headers={"Authorization": f"Api-Token {DT_TOKEN}",
                 "Content-Type":  "text/plain; charset=utf-8"},
    )
    with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as r:
        return r.status, r.read().decode()


def main():
    now_ms = int(time.time() * 1000)
    all_lines, totals = [], {}
    for m in MAPPINGS:
        rows = dqlquery(m["query"])
        emitted = 0
        for r in rows:
            try:
                if m.get("value_from_record"):
                    v  = m["value"](r)
                    ts = now_ms   # fetch rows don't carry a bucket timeframe; stamp as "now"
                else:
                    v, ts = latest_point(r.get("val"), r.get("timeframe", {}))
                if v is None or ts is None:
                    continue
                dims = m["dims"](r)
                if not dims.get("device.address"):
                    continue
                all_lines.append(line(m["key"], dims, v, ts))
                emitted += 1
            except Exception as e:
                print(f"  skip row ({m['key']}): {e}", file=sys.stderr)
        totals[m["key"]] = (len(rows), emitted)

    for k, (rows, emitted) in totals.items():
        print(f"  {k:30s}  rows={rows:>4}  emitted={emitted:>4}")

    if DRY_RUN:
        print(f"\n[dry-run] {len(all_lines)} lines; first 3:")
        for l in all_lines[:3]:
            print("  " + l)
        return
    if not all_lines:
        print("nothing to ingest")
        return
    status, body = ingest(all_lines)
    print(f"\ningested {len(all_lines)} lines → HTTP {status} {body[:120]}")


if __name__ == "__main__":
    main()
