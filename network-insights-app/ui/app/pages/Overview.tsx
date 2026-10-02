import React from "react";
import { useNavigate } from "react-router-dom";
import { Flex } from "@dynatrace/strato-components/layouts";
import { Heading, Text, Paragraph } from "@dynatrace/strato-components/typography";
import { useDql } from "@dynatrace-sdk/react-hooks";
import { t, mono } from "../theme";
import { Panel, StatTile, Tag, Pill, QueryErr } from "../components/ui";
import { fmt, badge } from "../lib/format";
import { useFleet, useDavis, useEvents, problemLink, fleetLogScope } from "../lib/data";
import { useSites, siteOf } from "../lib/sites";
import { useTimeframe } from "../lib/timeframe";

const summaryDql = (tf: string, scope: string) => `fetch logs, from:${tf}
| filter log.source == "network.config" or log.source == "network.compliance"
${scope}
| summarize changes=countIf(log.source=="network.config"),
           passes=countIf(\`compliance.status\`=="pass"),
           // denominator = controls actually EVALUATED. not_assessed (no rule set for the
           // platform), not_applicable and the unverified_ruleset notice are records, not
           // checks — counting them would silently deflate the score.
           checks=countIf(\`compliance.status\`=="pass" or \`compliance.status\`=="fail"),
           unassessed=countIf(\`compliance.status\`=="not_assessed")`;


export const Overview = () => {
  const dev = useFleet();
  const { map } = useSites();
  const { tf } = useTimeframe();
  const sum = useDql({ query: summaryDql(tf, fleetLogScope(dev.rows)) });
  const davis = useDavis();
  const paging = useEvents();
  const nav = useNavigate();

  // "DOWN" MEANS WE POLLED IT AND IT DID NOT ANSWER — not "we never polled it".
  //
  // useFleet merges in LLDP-discovered neighbours with monitored:false, and its own comment is
  // explicit that "up:false here means UNKNOWN, not down — callers must branch on `monitored`
  // before reporting a device as failed". This page did not: `down = devices.length - up` swept
  // every unmonitored neighbour into the Down tile.
  //
  // Measured 2026-08-03: `transformers` (192.168.1.1), a neighbour one of the switches sees over
  // LLDP on a subnet we deliberately do not poll, was being reported as "1 down · need attention".
  // That is a standing false alarm that appears the moment LLDP discovers anything beyond the
  // monitored fleet — and a Down tile that cries wolf is worth less than no tile at all.
  //
  // Unmonitored devices stay VISIBLE (they are real, and worth onboarding) but are counted
  // separately and excluded from the reachability percentage, whose denominator is now what we
  // actually poll.
  const devices = dev.rows;
  const monitored = devices.filter((d) => d.monitored);
  const unmonitored = devices.length - monitored.length;
  const up = monitored.filter((d) => d.up).length;
  const down = monitored.length - up;
  const pctUp = monitored.length ? Math.round((100 * up) / monitored.length) : 0;
  const empty = !dev.isLoading && devices.length === 0;
  // worst first in the status strip: down (0) before unpolled (1) before up (2)
  const rank = (d: { monitored?: boolean; up?: boolean }) => (!d.monitored ? 1 : d.up ? 2 : 0);
  const s = (sum.data as any)?.records?.[0] ?? {};
  // DQL summarize returns counts as STRINGS ("0", "42"), not numbers. The string "0" is truthy
  // in JS, so a bare `s.checks ?` enters the division branch and computes 100 * "0" / "0" → NaN,
  // which rendered as "NaN%" on a tenant with zero compliance logs. Coerce first.
  const checks  = Number(s.checks)  || 0;
  const passes  = Number(s.passes)  || 0;
  const changes = Number(s.changes) || 0;
  // null, NOT 0. Zero checks means the compliance track was never set up — it does NOT mean the
  // fleet failed every control. Rendering "0%" in green claimed both at once, on the landing page,
  // to a customer whose only mistake was not having reached that setup step yet.
  const pct = checks ? Math.round((100 * passes) / checks) : null;
  const problems: any[] = davis.rows;
  const active = problems.filter((p) => p.status === "ACTIVE").length;
  // Prefer a currently-active problem for the "Active alerts" panel; fall back to the most
  // recent root-caused one (with its status shown) so recent RCA activity stays visible.
  const top = problems.find((p) => p.status === "ACTIVE") ?? problems[0];
  const events: any[] = paging.rows;

  // per-site rollup: total + how many are down, so a site with an outage reads red at a glance.
  // Same rule as the tiles above — only MONITORED devices can be down, or a site would light up
  // red purely because LLDP found a neighbour there that nobody asked us to poll.
  const bySite: Record<string, { total: number; down: number }> = {};
  monitored.forEach((d) => { const st = siteOf(map, d.ip, d.device); const rec = bySite[st] || (bySite[st] = { total: 0, down: 0 }); rec.total++; if (!d.up) rec.down++; });
  const siteList = Object.keys(bySite).sort();

  return (
    <Flex flexDirection="column" gap={16} padding={24}>
      <div>
        <Heading level={2}>Network Insights</Heading>
        <Paragraph>Fleet health at a glance — live.</Paragraph>
      </div>

      {/* Loading is its OWN branch, ahead of empty. The fleet count depends on two fetches — the
          roster and the monitoring configurations — and the second one decides which rows survive.
          Rendering tiles from a half-arrived answer showed the fleet at its unfiltered size and
          then dropped it to the real one a moment later: the "flashes up then disappears" report.
          A number that is about to change is worse than no number. */}
      {dev.isLoading ? (
        <Panel>
          <Flex gap={12} flexWrap="wrap" style={{ padding: "4px" }}>
            {[0, 1, 2, 3].map((i) => (
              <div key={i} style={{ flex: "1 1 150px", height: 74, borderRadius: 10, background: t.subtle, opacity: 0.12 }} />
            ))}
          </Flex>
        </Panel>
      ) : empty ? (
        <Panel>
          <Flex flexDirection="column" gap={8} style={{ padding: "18px 4px", alignItems: "center", textAlign: "center" }}>
            <Text style={{ fontSize: 32 }}>📡</Text>
            <Text style={{ fontWeight: 700, fontSize: 17 }}>No devices monitored yet</Text>
            <Text style={{ color: t.subtle, fontSize: 14, maxWidth: 460 }}>Once your ActiveGate and the SNMP extension are polling, the fleet lights up here. The guided setup walks you through onboarding your first devices.</Text>
            <button onClick={() => nav("/setup")} style={{ marginTop: 4, background: t.accent, color: "#fff", border: 0, borderRadius: 8, padding: "10px 18px", fontSize: 15, fontWeight: 600, cursor: "pointer" }}>Open the setup wizard →</button>
          </Flex>
        </Panel>
      ) : (
      <>
      <Flex gap={12} flexWrap="wrap">
        <StatTile label="Devices" value={devices.length} sub="answering SNMP" accent={t.accent} />
        <StatTile label="Up" value={up} sub={`${pctUp}% of ${monitored.length} monitored`} accent={t.up} />
        <StatTile label="Down" value={down} sub={down ? "need attention" : "all reachable"} accent={down ? t.down : t.up} />
        {/* Discovered but not polled. Shown rather than hidden — these are real devices worth
            onboarding — but deliberately neutral-coloured, because "we never asked" is not a fault. */}
        {unmonitored ? (
          <StatTile label="Not monitored" value={unmonitored} sub="seen via LLDP · not polled" accent={t.subtle} />
        ) : null}
        <StatTile label="Config changes (24h)" value={changes}
                  sub={checks ? "tracked with diff" : "not set up yet"}
                  accent={changes ? t.warn : t.subtle} />
        <StatTile label="ISO compliance" value={pct == null ? "—" : `${pct}%`}
                  sub={pct == null ? "not set up yet" : `${checks} checks`}
                  accent={pct == null ? t.subtle : pct >= 90 ? t.up : pct >= 70 ? t.warn : t.down} />
      </Flex>

      <Flex gap={16} flexWrap="wrap" alignItems="stretch">
        <div style={{ flex: "2 1 480px", minWidth: 320, display: "flex", flexDirection: "column", gap: 16 }}>
          <Panel title="Sites" tag={<Tag>live</Tag>}>
            {dev.error ? (
              <QueryErr label="sites" />
            ) : dev.isLoading ? (
              <Text style={{ color: t.subtle }}>Loading…</Text>
            ) : (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(190px, 1fr))", gap: 12 }}>
                {siteList.map((st) => {
                  const rec = bySite[st]; const hasDown = rec.down > 0; const upN = rec.total - rec.down;
                  return (
                    <div key={st} style={{ border: `1px solid ${hasDown ? t.down : t.border}`, borderRadius: 8, padding: 14, background: t.cardSubtle }}>
                      <Flex justifyContent="space-between" alignItems="center" style={{ marginBottom: 10 }}>
                        <Text style={{ fontWeight: 700, fontSize: 16 }}>{st}</Text>
                        <Pill status={hasDown ? "down" : "up"}>{hasDown ? `${rec.down} down` : "Up"}</Pill>
                      </Flex>
                      <div style={{ height: 6, borderRadius: 3, background: hasDown ? t.down : t.up, marginBottom: 8 }} />
                      <Text style={{ color: t.subtle, fontSize: 13 }}>{rec.total} devices · <span style={{ color: hasDown ? t.down : t.up }}>{upN} up{hasDown ? `, ${rec.down} down` : ""}</span></Text>
                    </div>
                  );
                })}
              </div>
            )}
          </Panel>

          <Panel title="Device status — all nodes" tag={<Tag>live</Tag>}>
            {dev.error ? (
              <QueryErr label="devices" />
            ) : dev.isLoading ? (
              <Text style={{ color: t.subtle }}>Loading…</Text>
            ) : (
              <>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(30px, 1fr))", gap: 6 }}>
                  {/* THREE states, not two. An LLDP-discovered device nobody polls has up=false, and
                      painting that red reported a DOWN DEVICE THAT IS NOT DOWN — we never asked it
                      anything. It also made this strip contradict the tiles directly above it, which
                      correctly read "Down 0 · all reachable" and "Not monitored 1" while one square
                      sat red. Unpolled is neutral: an onboarding gap, not a fault.
                      Worst first: down, then unpolled, then up. */}
                  {[...devices].sort((a, b) => rank(a) - rank(b)).map((d, i) => {
                    const state  = !d.monitored ? "not polled" : d.up ? "up" : "down";
                    const colour = !d.monitored ? t.subtle : d.up ? t.up : t.down;
                    return (
                    <div key={i} title={`${d.label || d.device} · ${state}`} onClick={() => nav(`/device/${encodeURIComponent(d.ip || d.device)}`)} style={{ aspectRatio: "1", borderRadius: 6, background: colour, cursor: "pointer" }} />);
                  })}
                </div>
                <Flex gap={16} style={{ marginTop: 12 }}>
                  <Text style={{ color: t.up, fontSize: 13 }}>■ up</Text>
                  <Text style={{ color: t.down, fontSize: 13 }}>■ down{down ? ` · ${down}` : ""}</Text>
                  {unmonitored ? <Text style={{ color: t.subtle, fontSize: 13 }}>■ not polled · {unmonitored}</Text> : null}
                </Flex>
              </>
            )}
          </Panel>
        </div>

        <div style={{ flex: "1 1 340px", minWidth: 300, display: "flex", flexDirection: "column", gap: 16 }}>
          <Panel title={`Active alerts (${active})`} tag={<Tag>Davis</Tag>}>
            {davis.error ? (
              <QueryErr label="alerts" />
            ) : davis.isLoading ? (
              <Text style={{ color: t.subtle }}>Loading…</Text>
            ) : !top ? (
              <Text style={{ color: t.subtle }}>All clear — no root-caused network problems (24h).</Text>
            ) : (
              <Flex gap={12} alignItems="flex-start">
                <div style={{ width: 4, alignSelf: "stretch", borderRadius: 3, background: top.status === "ACTIVE" ? t.down : t.subtle, flex: "none" }} />
                <div>
                  <Text style={{ fontWeight: 650, fontSize: 14 }}>{top.name}</Text>
                  <div style={{ color: t.subtle, fontSize: 13, margin: "4px 0 8px" }}>
                    The root-cause analysis correlated the signals into one problem and named the cause. Downstream devices are suppressed as symptoms, not paged.
                  </div>
                  <Flex gap={8} flexWrap="wrap">
                    <span style={{ fontSize: 12, fontWeight: 600, padding: "3px 9px", borderRadius: 6, color: top.status === "ACTIVE" ? t.warn : t.subtle, background: top.status === "ACTIVE" ? t.warnBg : t.cardSubtle }}>{top.status}</span>
                    {top.root ? <span style={{ fontSize: 12, fontWeight: 600, padding: "3px 9px", borderRadius: 6, color: t.down, background: t.downBg }}>root · {top.root}</span> : null}
                    {problemLink(top.pid) ? (
                      <a href={problemLink(top.pid)} target="_top" style={{ ...mono, fontSize: 12, color: t.accent, alignSelf: "center", textDecoration: "none" }}>{top.id} ↗</a>
                    ) : (
                      <span style={{ ...mono, fontSize: 12, color: t.subtle, alignSelf: "center" }}>{top.id}</span>
                    )}
                  </Flex>
                </div>
              </Flex>
            )}
          </Panel>

          <Panel title="Live paging — traps & syslog" tag={<Tag>live</Tag>}>
            {paging.error ? (
              <QueryErr label="paging" />
            ) : paging.isLoading ? (
              <Text style={{ color: t.subtle }}>Loading…</Text>
            ) : (
              <Flex flexDirection="column">
                {events.slice(0, 7).map((r, i) => {
                  const [label, color] = badge(r.source);
                  return (
                    <Flex key={i} gap={12} alignItems="baseline" style={{ padding: "6px 0", borderBottom: `1px solid ${t.border}` }}>
                      <Text style={{ ...mono, color: t.subtle, fontSize: 12, minWidth: 100 }}>{fmt(r.timestamp)}</Text>
                      <Text style={{ ...mono, color, fontWeight: 700, fontSize: 12, minWidth: 54 }}>{label}</Text>
                      <Text style={{ ...mono, fontSize: 12 }}>{r.content}</Text>
                    </Flex>
                  );
                })}
              </Flex>
            )}
          </Panel>
        </div>
      </Flex>
      </>
      )}
    </Flex>
  );
};
