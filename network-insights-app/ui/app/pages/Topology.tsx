import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { useDql } from "@dynatrace-sdk/react-hooks";
import { t } from "../theme";
import { Panel, Tag, Segmented, QueryErr } from "../components/ui";
import { reconcileEdges, type Prov } from "../lib/metrics";
import { useRoles, roleFor, glyph } from "../lib/roles";
import { useFleet, deviceLabel } from "../lib/data";
import { useSites, siteOf } from "../lib/sites";
import { useAcknowledgedDevices } from "../lib/lifecycle";

// THIS GRAPH IS KEYED ON device.address, NOT ON THE NAME.
//
// It used to join edges to devices by sys_name, and that broke in two visible ways the moment
// a switch was renamed (observed live 2026-08-01):
//   * the fleet roster still carried the OLD name while LLDP edges already carried the NEW one,
//     so no edge endpoint matched a device — the site view rendered "0 edges · no cabling in
//     this location" while the devices sat there, and the SAME devices appeared again under
//     "Unassigned" (where their edges DID draw, because both ends were unresolvable);
//   * two sources naming one device differently (a Netgear reporting sysName "n/a" vs this
//     app's IP fallback) drew it as two nodes.
// Both are the same defect. Addresses are unique by construction — they are what the extension
// builds entity ids from (idPattern: network_device_{device.address}) and what roles and sites
// are keyed on — so the name is now a LABEL ONLY and never a join key.
/* BOUNDED, AND HONEST ABOUT IT. This query had no limit: fine at the 15 edges the lab emits
   today, but the whole point of the site work is to grow the estate, and an unbounded topology
   query degrades by drawing a slower and slower picture rather than by failing — the worst
   failure mode to notice late. EDGE_LIMIT+1 is requested so the caller can tell "exactly at the
   cap" from "over it" and say so on screen, rather than silently drawing a partial network and
   letting it read as the whole one. Same rule as everywhere else in this app: a truncation
   nobody can see is a lie. */
export const EDGE_LIMIT = 400;
const EDGES_Q = `timeseries e=count(cno.dep.uses), by:{\`device.address\`,\`upstream.address\`,\`device.name\`,\`upstream.name\`,link_type,discovery}, from:-2h
| fieldsAdd n=arraySum(e) | filter n>0
| fields down=\`device.address\`, up=\`upstream.address\`, downName=\`device.name\`, upName=\`upstream.name\`, link_type, discovery
| limit ${EDGE_LIMIT + 1}`;
// SAFE multi-aggregate: both metrics come from the SAME SNMP subgroup and are emitted in one
// poll, so a series can never carry one without the other (measured equal). If you add a
// metric from a DIFFERENT group here it becomes an inner join and starts dropping rows —
// use outerTs() from lib/netflow.ts instead. See the note there.
const THROUGHPUT_Q = `timeseries inb=max(cno.if.in_octets.count), outb=max(cno.if.out_octets.count), by:{\`device.address\`}, from:-30m, interval:5m
| fieldsAdd mbps = (arrayAvg(arrayDelta(inb)) + arrayAvg(arrayDelta(outb)))*8/1000000/300
| filter mbps>0 | fields device=\`device.address\`, mbps`;


const W = 1000, H = 600, R = 22;
const TIERY: Record<string, number> = { "wan-edge": 70, core: 210, access: 350, ap: 490, console: 490, other: 350 };
// A tier with more nodes than this wraps onto multiple rows so they do not pile on top of
// each other. 15 at R=22 across the 880px span gives ~55px per node — enough gap to read labels
// without the ring overlap seen on big fleets (observed with 65 FortiGate branches on one tier).
const MAX_PER_ROW = 15;
const ROW_H = 70; // vertical offset per extra row within a tier

export const Topology = () => {
  const nav = useNavigate();
  const edgesQ = useDql({ query: EDGES_Q });
  const reachQ = useFleet();
  const thruQ = useDql({ query: THROUGHPUT_Q });

  // reachQ (useFleet) already excludes retired devices at the source — see lib/data.ts.
  // EDGES_Q does not: it reads cno.dep.uses directly from Grail over a 2h window, and that
  // window has no idea a device was retired — an extension can keep emitting an edge for a
  // device right up to the moment its config was deleted, so a just-acknowledged address can
  // still be sitting in the last two hours of edge history. App-state (the acknowledge flag)
  // is not something DQL can filter on, so it is applied here, client-side, before anything
  // downstream (nodes, names, sites) is built from these edges.
  const { acked } = useAcknowledgedDevices();
  const returnedEdges: any[] = (edgesQ.data as any)?.records ?? [];
  // Over the cap means the picture is INCOMPLETE. Surfaced below rather than drawn silently.
  const edgesTruncated = returnedEdges.length > EDGE_LIMIT;
  const rawEdges: any[] = returnedEdges.slice(0, EDGE_LIMIT).filter(
    (e: any) => !acked[String(e.down)] && !acked[String(e.up)],
  );
  const reach = reachQ.rows;
  const thru: any[] = (thruQ.data as any)?.records ?? [];

  // everything below is keyed on the management ADDRESS — see the note on EDGES_Q
  //
  // THREE states, not two. "We do not poll this device" is not the same claim as "this device
  // is down", and the graph used to render them identically. Anything that appears only as an
  // LLDP neighbour — an unmanaged switch, the UniFi gateway at 192.168.1.1 — was absent from
  // the roster, therefore absent from `answering`, therefore drawn RED as though it had
  // failed. We had never contacted it and had no basis for that claim.
  //   monitored + recent data   -> up          (green)
  //   monitored + no data       -> down        (red)    a real, earned assertion
  //   not in our roster         -> unmonitored (grey)   we genuinely do not know
  // This also unblocks consuming other data sources: a device someone else polls stops being
  // reported as broken by us.
  const answering = new Set(reach.filter((r) => r.up).map((r) => String(r.ip)));
  const monitored = new Set(reach.filter((r) => r.monitored).map((r) => String(r.ip)));
  const mbpsOf: Record<string, number> = {};
  thru.forEach((r) => { mbpsOf[String(r.device)] = Math.round(Number(r.mbps) || 0); });

  // Display name per address. The fleet wins (it already resolves the CURRENT sys_name and
  // falls back to the IP for unnamed gear); edges supply names for UNMANAGED neighbours that
  // LLDP found but we never poll, so they are not nameless on screen.
  const nameOf: Record<string, string> = {};
  rawEdges.forEach((e) => {
    if (e.down && e.downName && !nameOf[e.down]) nameOf[e.down] = String(e.downName);
    if (e.up && e.upName && !nameOf[e.up]) nameOf[e.up] = String(e.upName);
  });
  reach.forEach((r) => { if (r.ip) nameOf[String(r.ip)] = r.label; });
  const labelFor = (a: string) => deviceLabel(nameOf[a], a);

  // nodes = devices in the cabling graph OR just reachable (standalone). The site
  // filter shows one location; edges render only when both endpoints are visible.
  const { map } = useSites();
  const { map: roleMap } = useRoles();
  const [site, setSite] = useState("");
  const allAddrs = new Set<string>();
  rawEdges.forEach((e) => { if (e.down) allAddrs.add(String(e.down)); if (e.up) allAddrs.add(String(e.up)); });
  reach.forEach((r) => { if (r.ip) allAddrs.add(String(r.ip)); });
  // sites and roles are BOTH keyed on the address already, so these are now direct lookups —
  // the name is passed only so pre-migration, name-keyed assignments still resolve.
  const siteFor = (a: string) => siteOf(map, a, nameOf[a]);
  const roleFn = (a: string) => roleFor(roleMap, a, nameOf[a]);
  const sites = Array.from(new Set(Array.from(allAddrs).map((a) => siteFor(a)))).sort();
  const activeSite = sites.includes(site) ? site : sites[0] || "";
  const names = new Set(Array.from(allAddrs).filter((a) => siteFor(a) === activeSite));
  // Collapse duplicates. A renamed device reports under BOTH names inside the 2h window, so the
  // same physical link arrives as several rows differing only in device.name — harmless when
  // drawn (identical path) but it double-counts in the "N edges" legend. Keyed on the addresses,
  // which is exactly what the rename does not change.
  // reconcileEdges / provenanceOf live in lib/metrics.ts so the duplicate-edge rule is testable.
  const visibleEdges = reconcileEdges(rawEdges.filter((e) => names.has(e.down) && names.has(e.up)));
  // Sources actually contributing to THIS view, not to the estate. Computed from rawEdges it read
  // "via API + LLDP + NetBox" on a Branch-B canvas whose single edge came from NetBox alone —
  // crediting two sources that found nothing here. Small, but it is the same overclaim this app
  // keeps having to remove: say what is true of what is on screen.
  const edgeSources = Array.from(
    new Set(visibleEdges.flatMap((e) => Array.from(e.sources as Set<string>))),
  ).sort();
  const SRC_LABEL: Record<string, string> = { lldp: "LLDP", netbox: "NetBox", api: "API" };
  const sourceLabel = edgeSources.map((x) => SRC_LABEL[x] || x).join(" + ");
  const provCount = (p: Prov) => visibleEdges.filter((e) => e.prov === p).length;

  const tierMembers: Record<string, string[]> = {};
  const powerNodes: string[] = [];
  Array.from(names).forEach((n) => {
    const r = roleFn(n);
    if (r === "pdu" || r === "ups") powerNodes.push(n);
    else (tierMembers[r] = tierMembers[r] || []).push(n);
  });
  /* TIERS COLLAPSE WHEN THEY ARE EMPTY. TIERY is a fixed ladder — wan-edge 70, core 210, access
     350, ap 490 — which is right for HQ, where every rung is occupied. Branch-B has a router and
     an AP and nothing between, so it drew them at 70 and 490 with 420px of blank canvas in the
     middle and a hairline crossing it. The hierarchy was technically correct and visually
     useless, which for the site whose whole job is to look DIFFERENT from HQ is the wrong
     failure. Rungs that exist keep their ORDER; the ladder just gets shorter. */
  const TIER_ORDER = ["wan-edge", "core", "access", "other", "ap", "console"];
  const occupied = TIER_ORDER.filter((r) => (tierMembers[r] || []).length);
  // Rows each tier will occupy once wrapped. The vertical layout accounts for this so a
  // crowded wan-edge does not visually crash into the tier below it.
  const rowsOf = (r: string) => Math.max(1, Math.ceil((tierMembers[r] || []).length / MAX_PER_ROW));
  const yOf: Record<string, number> = {};
  if (occupied.length === 1) {
    yOf[occupied[0]] = 280;
  } else {
    const top = 70;
    let cursor = top;
    occupied.forEach((r, i) => {
      yOf[r] = cursor;
      cursor += rowsOf(r) * ROW_H + (i < occupied.length - 1 ? 60 : 0); // tier gap only between tiers
    });
  }
  const pos: Record<string, { x: number; y: number }> = {};
  // One wrap-aware layout per tier (not per base-Y, because wrapping produces several Y bands
  // within a tier). Keyed on tier, not on yOf[r], so power nodes added later cannot collide.
  Object.keys(tierMembers).forEach((r) => {
    const arr = tierMembers[r].slice().sort();
    const tierY = yOf[r] ?? TIERY[r] ?? 350;
    const span = 880; // widened from 560 so even full rows have breathing room
    const rows = Math.ceil(arr.length / MAX_PER_ROW);
    arr.forEach((n, i) => {
      const row = Math.floor(i / MAX_PER_ROW);
      // Last row can be short; distribute whichever count it actually has across the span.
      const rowStart = row * MAX_PER_ROW;
      const rowCount = Math.min(MAX_PER_ROW, arr.length - rowStart);
      const col = i - rowStart;
      const x = rowCount === 1 ? W / 2 : 60 + (span * col) / (rowCount - 1);
      const y = tierY + row * ROW_H;
      pos[n] = { x, y };
    });
  });
  // Dynamic viewBox height — the fixed H=600 clipped the bottom tier when a tier wrapped.
  const maxY = Math.max(H, ...Object.values(pos).map(p => p.y + R + 40), 600);
  powerNodes.sort().forEach((n, i) => { pos[n] = { x: 910, y: 250 + i * 150 }; });

  // WAN uplinks: cross-site edges touching this site (branch SDWAN <-> HQ hub). The per-site view
  // can't place the remote device, so draw it as a "WAN -> <site>" node above the local uplink.
  const wanEdges = reconcileEdges(rawEdges.filter((e) => names.has(e.down) !== names.has(e.up)));
  const wanPos: Record<string, { x: number; y: number }> = {};
  const wanRemotes = Array.from(new Set(wanEdges.map((e) => String(names.has(e.down) ? e.up : e.down)))).sort();
  wanRemotes.forEach((r, i) => { wanPos[r] = { x: wanRemotes.length === 1 ? W / 2 : 180 + (560 * i) / (wanRemotes.length - 1), y: 22 }; });

  const isLoading = edgesQ.isLoading || reachQ.isLoading;
  const qErr = edgesQ.error || reachQ.error || thruQ.error;
  const stateOf = (a: string): "up" | "down" | "unmonitored" =>
    !monitored.has(a) ? "unmonitored" : answering.has(a) ? "up" : "down";
  const statusColor = (a: string) =>
    ({ up: t.up, down: t.down, unmonitored: t.subtle } as const)[stateOf(a)];

  // pan + zoom on the clean SVG (buttons + drag) — keeps the mockup look, restores controls
  const [view, setView] = useState({ s: 1, x: 0, y: 0 });
  // Label visibility toggles. Device-name and IP each have their own switch so an operator can
  // trade a dense fleet for readability without zooming.
  const [showNames, setShowNames] = useState(true);
  const [showIps, setShowIps] = useState(true);
  const drag = useRef<{ sx: number; sy: number; ox: number; oy: number } | null>(null);
  const zoom = (f: number) => setView((v) => ({ ...v, s: Math.min(4, Math.max(0.4, v.s * f)) }));
  const onDown = (e: React.MouseEvent) => { drag.current = { sx: e.clientX, sy: e.clientY, ox: view.x, oy: view.y }; };
  const onMove = (e: React.MouseEvent) => { if (drag.current) setView((v) => ({ ...v, x: drag.current!.ox + (e.clientX - drag.current!.sx), y: drag.current!.oy + (e.clientY - drag.current!.sy) })); };
  const onUp = () => { drag.current = null; };
  const btn: React.CSSProperties = { width: 30, height: 30, borderRadius: 7, border: `1px solid ${t.border}`, background: t.cardSubtle, color: t.ink, cursor: "pointer", fontSize: 16, lineHeight: "1", display: "flex", alignItems: "center", justifyContent: "center" };
  const edgePath = (a: { x: number; y: number }, b: { x: number; y: number }, power: boolean) =>
    power
      ? `M ${a.x} ${a.y} C ${(a.x + b.x) / 2} ${a.y}, ${(a.x + b.x) / 2} ${b.y}, ${b.x} ${b.y}`
      : `M ${a.x} ${a.y} C ${a.x} ${(a.y + b.y) / 2}, ${b.x} ${(a.y + b.y) / 2}, ${b.x} ${b.y}`;

  return (
    <Flex flexDirection="column" gap={16} padding={24}>
      <div>
        <Heading level={2}>Topology</Heading>
        <Paragraph>Live dependency graph — cabling (data + power) with throughput on the links. Edges are discovered from NetBox or LLDP (the devices' own neighbor tables); reachable devices without cabling show as standalone nodes.</Paragraph>
      </div>

      {sites.length > 1 ? (
        <Segmented options={sites.map((s) => ({ value: s, label: s }))} value={activeSite} onChange={setSite} />
      ) : null}

      {/* Say it out loud when the drawing is partial. */}
      {edgesTruncated ? (
        <div style={{ border: `1px solid ${t.warn}33`, background: t.warnBg, borderRadius: 8,
                      padding: "8px 12px", fontSize: 13, color: t.subtle }}>
          <Text style={{ color: t.warn, fontWeight: 600 }}>Showing the first {EDGE_LIMIT} links.</Text>{" "}
          The estate has more than this view draws — filter by site to see a complete picture of one location.
        </div>
      ) : null}

      <Panel title={`${activeSite || "—"} — data path + power domain`} tag={<Tag>live</Tag>}>
        {qErr ? (
          <QueryErr label="topology" />
        ) : isLoading ? (
          <Text style={{ color: t.subtle }}>Loading…</Text>
        ) : names.size === 0 ? (
          <Text style={{ color: t.subtle }}>No devices in this view.</Text>
        ) : (
          <div style={{ position: "relative", width: "100%", margin: "0 auto" }}>
            <div style={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 10, zIndex: 2, alignItems: "center",
                          background: t.card, border: `1px solid ${t.border}`, borderRadius: 7, padding: "4px 8px" }}>
              <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 12, color: t.ink, cursor: "pointer", userSelect: "none" }}>
                <input type="checkbox" checked={showNames} onChange={(e) => setShowNames(e.target.checked)} />
                names
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 12, color: t.ink, cursor: "pointer", userSelect: "none" }}>
                <input type="checkbox" checked={showIps} onChange={(e) => setShowIps(e.target.checked)} />
                IPs
              </label>
              <button aria-label="Zoom in" onClick={() => zoom(1.2)} style={btn}>+</button>
              <button aria-label="Zoom out" onClick={() => zoom(1 / 1.2)} style={btn}>−</button>
              <button aria-label="Reset view" onClick={() => setView({ s: 1, x: 0, y: 0 })} style={btn}>⟲</button>
            </div>
            <svg
              viewBox={`0 0 ${W} ${maxY}`}
              width="100%"
              role="img"
              aria-label="Network topology"
              onMouseDown={onDown}
              onMouseMove={onMove}
              onMouseUp={onUp}
              onMouseLeave={onUp}
              style={{ cursor: drag.current ? "grabbing" : "grab", touchAction: "none", userSelect: "none" }}
            >
              <g transform={`translate(${view.x} ${view.y}) scale(${view.s})`}>
              {visibleEdges.map((e, i) => {
                const a = pos[e.down], b = pos[e.up];
                if (!a || !b) return null;
                const power = e.link_type === "power";
                /* Provenance is drawn, not just recorded. An UNDOCUMENTED link — one the devices
                   report but the CMDB has never heard of — is the single most useful thing this
                   view can tell an engineer, so it gets its own colour and a label rather than
                   looking like every other line. UNDISCOVERED is the mirror: documented cabling
                   the device never advertised, which is either an AP that does not speak LLDP or
                   a link that is actually down. Both are muted; only the undocumented one shouts,
                   because only it is news. */
                const color = power ? t.warn
                  : e.prov === "undocumented" ? t.warn
                  : e.prov === "undiscovered" ? t.subtle
                  : t.accent;
                const dash = power ? "6 5"
                  : e.prov === "undocumented" ? "5 3"
                  : e.prov === "undiscovered" ? "2 4"
                  : undefined;
                const mb = mbpsOf[String(e.down)];
                const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
                const label = power ? ""
                  : e.prov === "undocumented" ? "undocumented"
                  : mb ? `${mb} Mbps` : "";
                return (
                  <g key={i}>
                    <path d={edgePath(a, b, power)} fill="none" style={{ stroke: color }} strokeWidth={e.prov === "undocumented" ? 2.2 : 1.6} strokeDasharray={dash} opacity={power ? 0.55 : e.prov === "undiscovered" ? 0.5 : 0.85} />
                    {label ? (
                      <g>
                        <rect x={mx - label.length * 3.6} y={my - 12} width={label.length * 7.2} height={16} rx={4} style={{ fill: t.card }} opacity={0.92} />
                        <text x={mx} y={my} textAnchor="middle" style={{ fill: t.subtle, fontSize: 11, fontFamily: "ui-monospace, monospace" }}>{label}</text>
                      </g>
                    ) : null}
                  </g>
                );
              })}
              {/* WAN uplinks to other sites (dashed accent -> a cloud node) */}
              {wanEdges.map((e, i) => {
                const local = names.has(e.down) ? e.down : e.up;
                const remote = names.has(e.down) ? e.up : e.down;
                const a = pos[local], b = wanPos[remote]; if (!a || !b) return null;
                return <path key={`we${i}`} d={edgePath(a, b, false)} fill="none" style={{ stroke: t.accent }} strokeWidth={1.6} strokeDasharray="2 4" opacity={0.65} />;
              })}
              {Object.entries(wanPos).map(([r, p]) => (
                <g key={`wn${r}`}>
                  <rect x={p.x - 40} y={p.y - 15} width={80} height={30} rx={15} style={{ fill: t.card, stroke: t.accent }} strokeWidth={1.5} strokeDasharray="2 3" />
                  <text x={p.x} y={p.y - 1} textAnchor="middle" style={{ fill: t.accent, fontSize: 10, fontWeight: 700, fontFamily: "ui-monospace, monospace" }}>☁ WAN</text>
                  <text x={p.x} y={p.y + 10} textAnchor="middle" style={{ fill: t.subtle, fontSize: 9, fontFamily: "ui-monospace, monospace" }}>→ {siteFor(r)}</text>
                </g>
              ))}
              {Object.keys(pos).map((n) => {
                const p = pos[n]; const c = statusColor(n); const st = stateOf(n);
                return (
                  <g key={n} onClick={(e) => { e.stopPropagation(); nav(`/device/${encodeURIComponent(n)}`); }} onMouseDown={(e) => e.stopPropagation()} style={{ cursor: "pointer" }}>
                    {/* dashed ring = we do not poll it, so its state is unknown rather than bad */}
                    <circle cx={p.x} cy={p.y} r={R} style={{ fill: t.card, stroke: c }} strokeWidth={2.5}
                            strokeDasharray={st === "unmonitored" ? "3 3" : undefined} />
                    <text x={p.x} y={p.y + 4} textAnchor="middle" style={{ fill: t.subtle, fontSize: 10, fontWeight: 700, fontFamily: "ui-monospace, monospace" }}>{glyph(roleFn(n))}</text>
                    {showNames ? <text x={p.x} y={p.y + R + 16} textAnchor="middle" style={{ fill: t.ink, fontSize: 12, fontWeight: 600, fontFamily: "ui-monospace, monospace" }}>{labelFor(n).replace("LAB-", "")}</text> : null}
                    {showIps && labelFor(n) !== n ? <text x={p.x} y={p.y + R + (showNames ? 30 : 16)} textAnchor="middle" style={{ fill: t.subtle, fontSize: 10, fontFamily: "ui-monospace, monospace" }}>{n}</text> : null}
                  </g>
                );
              })}
              </g>
            </svg>
          </div>
        )}
      </Panel>
      <Flex gap={16} flexWrap="wrap">
        <Text style={{ color: t.up, fontSize: 13 }}>● up</Text>
        <Text style={{ color: t.down, fontSize: 13 }}>● down</Text>
        <Text style={{ color: t.subtle, fontSize: 13 }}>◌ not monitored</Text>
        <Text style={{ color: t.accent, fontSize: 13 }}>— data (Mbps)</Text>
        <Text style={{ color: t.warn, fontSize: 13 }}>··· power</Text>
        {wanEdges.length ? <Text style={{ color: t.accent, fontSize: 13 }}>┈ WAN uplink</Text> : null}
        <Text style={{ color: t.subtle, fontSize: 13 }}>{visibleEdges.length} {visibleEdges.length === 1 ? "edge" : "edges"}{wanEdges.length ? ` + ${wanEdges.length} WAN` : ""} · {Object.keys(pos).length} devices{(() => { const u = Object.keys(pos).filter((n) => stateOf(n) === "unmonitored").length; return u ? ` (${u} not monitored)` : ""; })()}{sourceLabel ? ` · via ${sourceLabel}` : ""}{(() => {
          // Drift, stated as a number. "3 undocumented" is a finding an engineer can act on;
          // burying it in edge styling alone makes it something you have to already be looking for.
          const u = provCount("undocumented"), d = provCount("undiscovered");
          return u || d ? ` · ${u ? `${u} undocumented` : ""}${u && d ? ", " : ""}${d ? `${d} not advertised` : ""}` : "";
        })()}</Text>
        {visibleEdges.length === 0 && names.size > 0 ? <Text style={{ color: t.warn, fontSize: 13 }}>no cabling in this location — links come from NetBox or LLDP</Text> : null}
      </Flex>
    </Flex>
  );
};
