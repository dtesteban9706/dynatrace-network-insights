import { httpClient } from '@dynatrace-sdk/http-client';

// Live provisioning against the SNMP extension's monitoring configurations
// (Extensions 2.0 platform API). Verified payload/response shapes:
//   POST  {BASE}          body {scope,value}        -> 201 { objectId }
//   GET   {BASE}                                    -> { items:[{objectId,scope,value}] }
//   DELETE {BASE}/{objectId}                        -> 200
// Each app-onboarded device is ONE single-device config (surgical add/retire).

// ── Deployment configuration ───────────────────────────────────────────────
// The ONLY environment-specific values. `extension` is the SNMP interface extension
// this app manages (ships with the app). `defaultScope` is a fallback ActiveGate
// group used only when no scope can be inferred from an existing config. Extension
// VERSION and SCOPE are otherwise read LIVE below (never hardcoded), so the app
// follows extension upgrades and uses the customer's real AG group automatically.
const CONFIG = {
  extension: 'custom:cno.network.interfaces',
  discoveryExtension: 'com.dynatrace.extension.snmp-auto-discovery',
  defaultScope: '', // no lab default — scope is inferred from an existing config, else the operator picks it (agGroups)
};

const mcUrl = (ext: string) => `/platform/extensions/v2/extensions/${ext}/monitoring-configurations`;
const EXT = CONFIG.extension;
const BASE = mcUrl(EXT);
const DISCO_EXT = CONFIG.discoveryExtension;
const DISCO_BASE = mcUrl(DISCO_EXT);

// Numeric per-component version compare. A plain sort is WRONG here: lexicographically
// "0.0.9" > "0.0.10", so an upgraded extension would look older than the one it replaced.
function cmpVersion(a: string, b: string): number {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d;
  }
  return 0;
}

// Highest INSTALLED version. Note "installed" != "active": uploading a bundle installs it, and a
// separate environmentConfiguration PUT activates it. Kept only as the fallback for extVersion().
async function installedVersion(ext: string): Promise<string | undefined> {
  const b: any = await (await httpClient.send({ url: `/platform/extensions/v2/extensions/${ext}`, method: 'GET' })).body('json');
  const versions = (b.items || []).map((i: any) => i.version).filter(Boolean);
  // Was versions[len-1] — assumed the API returns ascending order, which it does not
  // guarantee. Getting this wrong pins NEW device configs to a stale extension version
  // on the core add-device path, silently.
  return versions.length ? versions.sort(cmpVersion)[versions.length - 1] : undefined;
}

// Live extension version — the ACTIVE one, not merely the newest installed.
//
// ⚠️ THIS DISTINCTION IS LOAD-BEARING AND USED TO BE WRONG HERE. In Extensions 2.0 the active
// version is a single environment-wide setting (see scripts/activate-ext-version.sh); every
// monitoring configuration runs at whatever is active. This function previously returned the
// highest INSTALLED version, which is a different question — "what is the newest bundle anyone
// has uploaded?" rather than "what is this tenant running?".
//
// The 0.0.14 migration procedure deliberately creates a window where they differ: step 2 is
// "upload 0.0.14 and do NOT activate yet". Throughout that window the old code returned 0.0.14
// while the tenant was still validating against 0.0.13's activation schema, so every device
// added through the app either (a) had its POST rejected for unknown featureSets enum values —
// the app's core onboarding path broken for the whole window — or (b) was accepted, stripped,
// and went dead the instant 0.0.14 went active, reporting OK, and invisible to the migration's
// before/after diff because it did not exist when the pre-flight snapshot was taken.
//
// FALLBACK DIRECTION IS DELIBERATE: if the active version cannot be read we fall back to the
// highest installed, which is always >= active. That errs toward SENDING featureSets, whose
// failure mode is a loud rejected POST, rather than omitting them, whose failure mode is a
// silently dead device. Loud beats silent.
async function extVersion(ext: string): Promise<string | undefined> {
  try {
    const r = await httpClient.send({ url: `/platform/extensions/v2/extensions/${ext}/environmentConfiguration`, method: 'GET' });
    const b = (await r.body('json')) as { version?: string } | undefined;
    if (b?.version) return b.version;
  } catch { /* not activated yet, or endpoint unavailable — fall through */ }
  return await installedVersion(ext);
}

// AG scope — reuse an existing config's scope so we never hardcode the customer's
// ActiveGate group; fall back to defaultScope only on a fresh install.
async function scopeFor(ext: string): Promise<string> {
  try {
    const b: any = await (await httpClient.send({ url: mcUrl(ext), method: 'GET' })).body('json');
    return (b.items || [])[0]?.scope || CONFIG.defaultScope;
  } catch { return CONFIG.defaultScope; }
}

// Anomaly detectors are metric-event Settings 2.0 objects.
const SETTINGS = '/platform/classic/environment-api/v2/settings/objects';
const METRIC_EVENTS_SCHEMA = 'builtin:anomaly-detection.metric-events';

// Credential Vault (classic env API). List returns metadata ONLY — id/name/type/scope, never the secret.
const CRED_URL = '/platform/classic/environment-api/v2/credentials';

// SNMP credential resolution (server-side, so no secret ships in the browser). The operator
// passes either a credential-vault id (CREDENTIALS_VAULT-…, the secure path) or a v2c community
// string; credAuth auto-detects which. These maps are OPTIONAL friendly-name registries, empty
// by default so nothing environment-specific is baked into the app.
const COMMUNITY: Record<string, string> = {};
const VAULT_IDS: Record<string, string> = {};

// SNMP auth resolution. Resolves (in order): a named vault profile → its vault id; a raw
// credential-vault id (CREDENTIALS_VAULT-…) → itself; else a profile → inline community.
// Vault mode references the credential by id and NEVER reads/writes the vault itself.
//
// Every shape below (field names, enum values, and which fields are legal for a given
// securityLevel) is taken from the datasource's own published config schema:
//   GET /api/v2/extensions/com.dynatrace.extension.snmp-generic-device/{version}/schema
//        → types['dynatrace.datasource.snmp:authentication']
// They are NOT guessed — the preconditions in that schema are what reject a config.
export type SecurityLevel = 'AUTH_PRIV' | 'AUTH_NO_PRIV' | 'NO_AUTH_NO_PRIV';
export type AuthProtocol = 'MD5' | 'SHA' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512';
export type PrivProtocol = 'DES' | 'AES' | 'AES192' | 'AES256' | 'AES192C' | 'AES256C';
export type SnmpV3Input = {
  userName?: string;
  securityLevel?: SecurityLevel;
  authProtocol?: AuthProtocol;
  authPassword?: string;
  privProtocol?: PrivProtocol;
  privPassword?: string;
};

function credAuth(profileId: string, snmpVersion?: 'v2c' | 'v3', v3?: SnmpV3Input) {
  const vaultId = VAULT_IDS[profileId] || (/^CREDENTIALS_VAULT-/i.test(profileId || '') ? profileId : '');

  // ── SNMPv3. Security-conscious customers mandate it (v2c authenticates in cleartext),
  // and the app previously had NO v3 path at all — every branch hardcoded SNMPv2c, so a
  // v3-only fleet could not be onboarded. Field names + enums come from the datasource
  // schema; note the vault field differs from v2c (credentialVaultIdSnmpV3, NOT
  // credentialVaultIdToken), and the schema's preconditions decide which fields may be
  // present for a given securityLevel — sending an auth/priv field the level does not
  // allow is a config rejection.
  if (snmpVersion === 'v3') {
    if (vaultId) return { type: 'SNMPv3', useCredentialVault: true, credentialVaultIdSnmpV3: vaultId };
    const level: SecurityLevel = v3?.securityLevel || 'AUTH_PRIV';
    const auth: Record<string, unknown> = {
      type: 'SNMPv3', useCredentialVault: false,
      userName: v3?.userName || '', securityLevel: level,
    };
    if (level === 'AUTH_PRIV' || level === 'AUTH_NO_PRIV') {
      auth.authProtocol = v3?.authProtocol || 'SHA';
      auth.authPassword = v3?.authPassword || '';
    }
    if (level === 'AUTH_PRIV') {
      auth.privProtocol = v3?.privProtocol || 'AES';
      auth.privPassword = v3?.privPassword || '';
    }
    return auth;
  }

  // ── SNMPv2c (unchanged). Vault mode references the credential by id; the app never
  // reads or writes the vault itself.
  if (vaultId) {
    return { type: 'SNMPv2c', useCredentialVault: true, credentialVaultIdToken: vaultId };
  }
  return { community: COMMUNITY[profileId] || profileId, type: 'SNMPv2c', useCredentialVault: false };
}

// Same concepts, DIFFERENT field names: the snmp-auto-discovery extension's
// `snmp_authentication` type uses `version`/`username`/`security_level`/`auth_*`/`priv_*`
// (snake_case) where the SNMP datasource uses `type`/`userName`/`securityLevel`/`authProtocol`
// (camelCase). Only the two credentialVault* fields are spelled the same. Sharing one builder
// between them would silently produce an invalid autodiscovery config, so they stay separate.
// Verified from GET /api/v2/extensions/com.dynatrace.extension.snmp-auto-discovery/{v}/schema.
function discoAuth(profileId: string, snmpVersion?: 'v2c' | 'v3', v3?: SnmpV3Input) {
  const vaultId = VAULT_IDS[profileId] || (/^CREDENTIALS_VAULT-/i.test(profileId || '') ? profileId : '');
  if (snmpVersion === 'v3') {
    if (vaultId) return { version: 'SNMPv3', useCredentialVault: true, credentialVaultIdSnmpV3: vaultId };
    const level: SecurityLevel = v3?.securityLevel || 'AUTH_PRIV';
    const a: Record<string, unknown> = {
      version: 'SNMPv3', useCredentialVault: false,
      username: v3?.userName || '', security_level: level,
    };
    if (level === 'AUTH_PRIV' || level === 'AUTH_NO_PRIV') {
      a.auth_protocol = v3?.authProtocol || 'SHA';
      a.auth_password = v3?.authPassword || '';
    }
    if (level === 'AUTH_PRIV') {
      a.priv_protocol = v3?.privProtocol || 'AES';
      a.priv_password = v3?.privPassword || '';
    }
    return a;
  }
  // v2c. This path previously ALWAYS inlined the community and never honoured a vault id,
  // making subnet autodiscovery the one onboarding route that bypassed the Credential Vault
  // (readiness item A4) — inconsistent with add-device and the API source, which both use it.
  if (vaultId) return { version: 'SNMPv2c', useCredentialVault: true, credentialVaultIdToken: vaultId };
  return { community: COMMUNITY[profileId] || profileId, version: 'SNMPv2c', useCredentialVault: false };
}

// ── Feature sets (SNMP extension ≥ 0.0.14) ────────────────────────────────────────────────
// From 0.0.14 the extension polls ONLY the OID groups a monitoring configuration selects.
// A config with no `featureSets` collects cno.device.uptime and NOTHING ELSE — and reports
// status OK while doing it. Omitting the key here would therefore make every device onboarded
// through this app silently dead on arrival: exactly the failure class the app exists to
// avoid. So we always send an explicit array.
//
// DEFAULT `['Interfaces']` covers the switch/router case this wizard is built for — cno.if.*
// plus the always-on uptime.
//
// ⚠️ IT IS NOT A DROP-IN REPLICA OF ≤0.0.13, and an earlier comment here wrongly said it
// reproduced that "EXACTLY". Under ≤0.0.13 `device-health/health` was ungated, so every config
// this wizard created ALSO collected cno.device.cpu_usage / memory_used / memory_free and the
// three com.dynatrace.extension.network_device.* copies. On non-Cisco gear that difference is
// invisible (those OIDs returned noSuchObject and produced nothing), but ON A CISCO DEVICE it is
// a real regression: add a Catalyst through Configure and its CPU and Memory tiles — and
// Dynatrace's own I&O Overview tiles, which read the com.dynatrace.extension.network_device.*
// prefix — stay permanently blank. Callers SHOULD pass featureSets explicitly; see the role map
// in ui/app/pages/Configure.tsx. This default is the floor, not the answer.
//
// It deliberately does NOT include the power sets (`UPS power` / `PDU power`); those are
// device-class choices. Never send `UPS battery voltage` blind — on an all-or-nothing SNMPv1
// agent an unimplemented OID fails the whole request and kills the other power metrics.
// See modules/snmp-interfaces-extension/extension/extension.yaml for the measurements.
const FEATURE_SETS_MIN_VERSION = '0.0.14';
const DEFAULT_FEATURE_SETS = ['Interfaces'];
// Version-guarded on the ACTIVE version (see extVersion above — not the newest installed): the
// enum values do not exist in ≤0.0.13's activation schema, so sending them against a tenant that
// has not yet ACTIVATED 0.0.14 would make the POST fail outright. Loud beats silent, but working
// beats both — while ≤0.0.13 is the active version the groups are still always-on, so omitting
// the key there is correct rather than lossy.
function featureSetsFor(version: string, requested?: string[]): string[] | undefined {
  if (cmpVersion(version, FEATURE_SETS_MIN_VERSION) < 0) return undefined;
  return requested?.length ? requested : DEFAULT_FEATURE_SETS;
}

type AddInput = { action: 'add'; name: string; ip: string; profileId: string; scope?: string; snmpVersion?: 'v2c' | 'v3'; v3?: SnmpV3Input; featureSets?: string[] };
type RetireInput = { action: 'retire'; ip: string; name?: string };
type CatalogInput = { action: 'catalog' };
type DiscoverInput = { action: 'discover'; subnet: string; profileId: string; label?: string; snmpVersion?: 'v2c' | 'v3'; v3?: SnmpV3Input };
type AnomalyInput = { action: 'anomalyDetectors' };
type ToggleInput = { action: 'toggleDetector'; objectId: string; enabled: boolean };
type AgGroupsInput = { action: 'agGroups' };
type CreateDetectorsInput = { action: 'createDetectors'; detectors: any[] };
type CredentialsInput = { action: 'credentials' };
type ConfiguredDevicesInput = { action: 'configuredDevices' };
type Input = AddInput | RetireInput | CatalogInput | DiscoverInput | AnomalyInput | ToggleInput | AgGroupsInput | CreateDetectorsInput | CredentialsInput | ConfiguredDevicesInput;

// Network-relevant extension name fragments — used to filter the installed catalog.
// fortigate: Dynatrace ships this as com.dynatrace.extension.fortigate (no "fortinet" in the
// name, so the vendor keyword alone misses it). unifi/ubiquiti: for custom:ubiquiti-unifi and
// any derivative. These are additive — removing any entry hides a vendor's configs from the
// "monitored" diagnostic without hiding its metric data, which is the exact confusing shape
// documented in docs/METRIC-CONTRACT.md §"The other rule: what you name your extension".
const NET_RX = /snmp|cisco|meraki|palo|fortinet|fortigate|arista|juniper|f5|netflow|sflow|network|unifi|ubiquiti/i;

export default async function (payload: Input | undefined = undefined) {
  const p = payload as Input;
  if (!p || !p.action) return { ok: false, error: 'missing action' };
  try {
    if (p.action === 'add') return await addDevice(p);
    if (p.action === 'retire') return await retireDevice(p);
    if (p.action === 'catalog') return await catalog();
    if (p.action === 'discover') return await discoverSubnet(p);
    if (p.action === 'anomalyDetectors') return await anomalyDetectors();
    if (p.action === 'toggleDetector') return await toggleDetector(p);
    if (p.action === 'agGroups') return await agGroups();
    if (p.action === 'createDetectors') return await createDetectors(p);
    if (p.action === 'credentials') return await listCreds();
    if (p.action === 'configuredDevices') return await configuredDevices();
    return { ok: false, error: `unknown action ${(p as any).action}` };
  } catch (e: any) {
    let detail: any; try { detail = await e.response.body('json'); } catch { /* ignore */ }
    return { ok: false, error: String(e?.message || e), status: e?.response?.status, detail };
  }
}


// Surface the network anomaly detectors (metric-event settings) so the Alerting
// branch can show what's watched + which use Davis auto-adaptive baselines vs static
// thresholds — the concrete anti-SolarWinds story.
async function anomalyDetectors() {
  const url = `${SETTINGS}?schemaIds=${METRIC_EVENTS_SCHEMA}&fields=objectId,value&pageSize=100`;
  const b: any = await (await httpClient.send({ url, method: 'GET' })).body('json');
  const rx = /cno\.|network|snmp|interface| device|bandwidth|packet|compliance|oper_status/i;
  const detectors: any[] = [];
  for (const it of (b.items || [])) {
    const v = it.value || {};
    if (!rx.test(JSON.stringify(v))) continue;
    const model = v.model || v.modelProperties?.type || v.monitoringStrategy?.type || '';
    detectors.push({ objectId: it.objectId, name: v.summary, model, enabled: !!v.enabled });
  }
  return { ok: true, detectors, total: (b.items || []).length };
}

// Turn an anomaly detector on/off — GET the settings object, flip enabled, PUT back.
async function toggleDetector(p: { objectId: string; enabled: boolean }) {
  if (!p.objectId) return { ok: false, error: 'missing objectId' };
  const obj: any = await (await httpClient.send({ url: `${SETTINGS}/${p.objectId}`, method: 'GET' })).body('json');
  const value = { ...obj.value, enabled: p.enabled };
  await httpClient.send({ url: `${SETTINGS}/${p.objectId}`, method: 'PUT', body: { value } });
  return { ok: true, objectId: p.objectId, enabled: p.enabled };
}

// List installed network-relevant extensions so the wizard can advise (not assume)
// which extensions are present vs. need installing from the Hub.
/* PAGING PARAM IS KEBAB-CASE ON THIS ENDPOINT, and getting it wrong is silent.
 * `?pageSize=200` is not rejected — it is IGNORED, and the endpoint falls back to its default
 * page of 25. With 31 extensions on this tenant the cut landed at exactly the point where
 * `com.dynatrace.*` gives way to `custom:*` alphabetically, so all five custom:cno.network.*
 * extensions were invisible. Nothing errored; the catalog just quietly described a different,
 * smaller estate than the one installed.
 *
 * Everything downstream inherited it. configuredDevices() iterates this list, so the app never
 * read a single CNO monitoring configuration: intent came from com.dynatrace.extension.
 * snmp-generic-device instead — a STALE config listing 10.0.40.x and 10.88.40.42 — which is why
 * a decommissioned address rendered as a live "down" fault while four correctly-configured
 * Branch-A devices rendered "not monitored".
 *
 * Fixed three ways, because a silent truncation should not be able to do this again:
 *   - the correct `page-size` parameter,
 *   - follow the pages rather than trusting one to be enough, and
 *   - union in the extensions this app OWNS, so its own configuration can never be hidden by a
 *     paging artefact whatever the catalog returns.
 */
const OWN_EXTENSIONS = [
  CONFIG.extension,
  'custom:cno.network.controlplane',
  'custom:cno.network.dependency',
  'custom:cno.network.compliance',
  CONFIG.discoveryExtension,
];

async function catalog() {
  const seen = new Set<string>();
  const installed: string[] = [];
  let page = 0;
  let nextKey: string | undefined;
  do {
    const q = nextKey ? `next-page-key=${encodeURIComponent(nextKey)}` : 'page-size=100';
    const res = await httpClient.send({ url: `/platform/extensions/v2/extensions?${q}`, method: 'GET' });
    const b: any = await res.body('json');
    const items: any[] = Array.isArray(b) ? b : (b.items || b.extensions || b.results || []);
    for (const e of items) {
      const name = e.extensionName || e.name;
      if (name && !seen.has(name) && NET_RX.test(name)) { seen.add(name); installed.push(name); }
    }
    nextKey = (b && !Array.isArray(b)) ? (b.nextPageKey || b['next-page-key']) : undefined;
  } while (nextKey && ++page < 20);
  // Never let paging hide our own extensions.
  for (const own of OWN_EXTENSIONS) if (own && !seen.has(own)) { seen.add(own); installed.push(own); }
  return { ok: true, installed: installed.sort() };
}

/* EVERY DEVICE SOMEBODY ASKED US TO POLL — the INTENT side of the device lifecycle.
 *
 * Absence of metrics means four different things and they are indistinguishable from the metric
 * alone: the device is down, it was retired, polling broke, or it was never onboarded. A pure
 * age rule ("silent 30 days = retired, hide it") resolves that ambiguity the WRONG way — a device
 * genuinely down for 31 days would be silently reclassified as retired and disappear, which is a
 * real outage erased by a cleanup rule.
 *
 * A monitoring configuration is a statement that somebody WANTS this device polled, and that is
 * separable from whether it answers. Cross-referenced with the metric roster it gives:
 *     configured + reporting  -> up
 *     configured + silent     -> DOWN, a fault, at ANY age. Never hidden.
 *     not configured + history-> decommissioned (retirement is the REMOVAL of intent)
 *     not configured + never  -> discovered only (an LLDP neighbour nobody polls)
 *
 * Age then decides prominence, never classification.
 */
async function configuredDevices() {
  const cat = await catalog();
  const exts: string[] = cat.installed || [];
  const out: { ip: string; extension: string; configId: string; description: string }[] = [];
  const skipped: string[] = [];

  // PARALLEL, not sequential. This used to await each extension in turn, which was tolerable at
  // the 6 extensions the truncated catalog returned and is not at 11 now that the paging bug is
  // fixed — the fix roughly doubled the length of a chain that was already the slowest call in
  // the app. Every consumer waits on this before painting, so its latency is the app's perceived
  // speed. The reads are independent; there was never a reason to serialise them.
  const perExt = await Promise.all(exts.map(async (ext) => {
    try {
      const b: any = await (await httpClient.send({ url: mcUrl(ext), method: 'GET' })).body('json');
      // TOLERATE EITHER SHAPE — /platform/extensions/v2/... and the classic API disagree, and a
      // bare `b.items` on the wrong one silently yields zero devices, which reads as "nothing is
      // configured" and once erased the entire fleet.
      const items: any[] = Array.isArray(b) ? b : (b.items || b.results || b.values || []);
      return { ext, items, err: null as string | null };
    } catch (e: any) {
      return { ext, items: [] as any[], err: String(e?.message || e).slice(0, 80) };
    }
  }));

  for (const { ext, items, err } of perExt) {
    // A failed READ and an extension with no configurations are different facts and must not
    // collapse into one. Swallowing both identically is what made a short fleet undiagnosable.
    if (err) { skipped.push(`${ext} (${err})`); continue; }
    if (!items.length) { skipped.push(ext); continue; }
    for (const it of items) {
      const v = it.value || {};
      // SNMP extensions carry a device list; the Python ones carry a deviceList string. Both are
      // statements of intent and both must count, or a controlplane-only device is misread as
      // decommissioned.
      const snmp = (v.snmp?.devices || []).map((d: any) => d.ip).filter(Boolean);
      const py = String(v.pythonRemote?.deviceList || '')
        .split(/[\n,]/).map((t: string) => t.trim().split(':')[0].trim()).filter(Boolean);
      // Vendor Python extensions (FortiGate, Meraki, UniFi, etc.) use pythonRemote.endpoints[]
      // where each entry carries the device address as `host` or embedded in `url`. Without this
      // path these devices read "not monitored" on the Fleet even when the configuration exists.
      const endpoints = (v.pythonRemote?.endpoints || []).map((e: any) => {
        if (e.host) return e.host;
        if (e.url) { try { return new URL(e.url).hostname; } catch { return ''; } }
        return '';
      }).filter(Boolean);
      for (const ip of [...snmp, ...py, ...endpoints]) {
        out.push({ ip, extension: ext, configId: it.objectId, description: v.description || '' });
      }
    }
  }
  return { ok: true, devices: out, scanned: exts.length, skipped };
}

async function addDevice(p: AddInput) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(p.ip)) return { ok: false, error: `invalid ip ${p.ip}` };
  const version = await extVersion(EXT);
  if (!version) return { ok: false, error: `could not resolve installed version of ${EXT}` };
  const scope = p.scope || await scopeFor(EXT); // operator's picked AG group, else inferred
  if (!scope) return { ok: false, error: 'No ActiveGate group selected — pick the AG group that should poll this device.' };
  const featureSets = featureSetsFor(version, p.featureSets);
  const value = {
    enabled: true,
    description: `CNO onboard: ${p.name} (${p.ip})`,
    version,
    activationContext: 'REMOTE',
    primaryFields: [],
    primaryTags: [],
    // Explicit, never omitted on ≥0.0.14 — see FEATURE_SETS_MIN_VERSION above.
    ...(featureSets ? { featureSets } : {}),
    snmp: { devices: [{ ip: p.ip, port: 161, authentication: credAuth(p.profileId, p.snmpVersion, p.v3), primaryFields: [], primaryTags: [] }] },
  };
  const res = await httpClient.send({ url: BASE, method: 'POST', body: { scope, value } });
  const b: any = await res.body('json');
  // featureSets is returned so the caller can SHOW what was actually enabled rather than
  // leaving the operator to assume a UPS is being polled for power.
  return { ok: true, objectId: b?.objectId, ip: p.ip, name: p.name, scope, featureSets };
}

// AG groups available to poll — derived from the scopes on existing SNMP-family
// monitoring configs (no extra API scope needed). Lets the operator pick where a
// new device is polled instead of assuming one.
async function agGroups() {
  const exts = [CONFIG.extension, CONFIG.discoveryExtension, 'com.dynatrace.extension.snmp-generic-device', 'com.dynatrace.extension.palo-alto-generic'];
  const scopes = new Set<string>();
  for (const ext of exts) {
    try {
      const b: any = await (await httpClient.send({ url: mcUrl(ext), method: 'GET' })).body('json');
      for (const it of (b.items || [])) if (it.scope && String(it.scope).startsWith('ag_group-')) scopes.add(it.scope);
    } catch { /* ignore */ }
  }
  const current = await scopeFor(CONFIG.extension); // the group this app's extension already polls from
  return { ok: true, current, groups: Array.from(scopes).sort().map((s) => ({ scope: s, group: s.replace(/^ag_group-/, '') })) };
}

// List Credential Vault entries (metadata only) so the onboarding pickers auto-populate — the operator
// selects by name instead of pasting a CREDENTIALS_VAULT-… id. Signing certificates are filtered out
// (not device/API auth). The app still references by id and never reads the secret.
async function listCreds() {
  const b: any = await (await httpClient.send({ url: CRED_URL, method: 'GET' })).body('json');
  // Only credentials an EXTENSION can actually authenticate with: EXTENSION_AUTHENTICATION scope and
  // not a signing/TLS certificate. Drops signing CAs and app-only (APP_ENGINE) tokens the operator
  // can't use here. (SNMP vs API isn't distinguishable in metadata — both are EXTENSION_AUTHENTICATION
  // TOKENs — so the operator picks by name; e.g. an SNMP read-only vs a controller API token.)
  const usable = (b.credentials || [])
    .filter((c: any) => {
      const scopes: string[] = c.scopes || (c.scope ? [c.scope] : []);
      return !/CERTIFICATE/i.test(String(c.type || '')) && scopes.includes('EXTENSION_AUTHENTICATION');
    })
    .map((c: any) => ({ id: c.id, name: c.name, type: c.type, scope: c.scope }));
  return { ok: true, credentials: usable, total: (b.credentials || []).length };
}

/* RETIRE = WITHDRAW INTENT, EVERYWHERE THE DEVICE IS CONFIGURED.
 *
 * The old version only ever deleted a SINGLE-DEVICE configuration and refused everything else
 * ("isn't app-managed"). That made retire unusable on any real fleet: configurations are grouped
 * — by role here, by site or credential elsewhere — so the common case is one device among ten,
 * and the answer was always no. It also looked at one extension, while a device is typically
 * configured in several (interfaces for metrics, controlplane for LLDP).
 *
 * Two operations, picked by what is actually there:
 *   the ONLY device in a config -> delete the configuration
 *   one of several             -> write the survivors back without it
 *
 * THE SURVIVORS CARRY MASKED COMMUNITIES and that is safe. A GET returns every secret as
 * ***…***, and the long-standing assumption here was that writing those back stores the mask
 * literally and kills polling for everyone else in the config. Measured 2026-08-05: it does not.
 * An unchanged PUT, and then a field change carrying eleven masked communities on the live
 * 11-device configuration, both left every device polling for ten minutes with the config OK.
 * The platform recognises the mask and keeps the stored secret. That measurement is what makes
 * this function possible; without it, removing one device from a shared config would mean
 * reconstructing ten credentials the app does not have.
 *
 * Deliberately NOT touched: the entity. It cannot be deleted (DELETE /api/v2/entities -> 405) and
 * never expires. Retire withdraws the INTENT to poll; hiding the leftover entity is the app's job
 * (fleetRowState: not configured + not reporting -> retired), and the acknowledgement the caller
 * records alongside this is what makes it immediate rather than eventual.
 */
async function retireDevice(p: RetireInput) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(p.ip)) return { ok: false, error: `invalid ip ${p.ip}` };
  const cat = await catalog();
  const removed: { extension: string; how: 'deleted' | 'removed'; configId: string }[] = [];
  const failed: { extension: string; error: string }[] = [];

  for (const ext of (cat.installed || [])) {
    let items: any[] = [];
    try {
      const b: any = await (await httpClient.send({ url: mcUrl(ext), method: 'GET' })).body('json');
      items = Array.isArray(b) ? b : (b.items || b.results || b.values || []);
    } catch { continue; }                      // extension with no readable configs: not an error

    for (const it of items) {
      const v = it.value || {};
      const devs: any[] = (v.snmp?.devices || []);
      const py = String(v.pythonRemote?.deviceList || '');
      const inSnmp = devs.some((d: any) => d.ip === p.ip);
      const inPy = py.split(/[\n,]/).map((t) => t.trim().split(':')[0].trim()).includes(p.ip);
      if (!inSnmp && !inPy) continue;

      const others = devs.filter((d: any) => d.ip !== p.ip);
      const pyOthers = py.split(/[\n,]/).map((t) => t.trim()).filter(Boolean)
        .filter((t) => t.split(':')[0].trim() !== p.ip);
      const nothingLeft = (inSnmp && others.length === 0 && !py) || (inPy && pyOthers.length === 0 && !devs.length);

      try {
        if (nothingLeft) {
          await httpClient.send({ url: `${mcUrl(ext)}/${it.objectId}`, method: 'DELETE' });
          removed.push({ extension: ext, how: 'deleted', configId: it.objectId });
        } else {
          const next = JSON.parse(JSON.stringify(v));
          if (inSnmp) next.snmp.devices = others;
          if (inPy) next.pythonRemote.deviceList = pyOthers.join('\n');
          await httpClient.send({
            url: `${mcUrl(ext)}/${it.objectId}`, method: 'PUT',
            body: { scope: it.scope, value: next },
          });
          removed.push({ extension: ext, how: 'removed', configId: it.objectId });
        }
      } catch (e: any) {
        failed.push({ extension: ext, error: String(e?.message || e).slice(0, 120) });
      }
    }
  }

  if (!removed.length && !failed.length) {
    return { ok: false, error: `${p.ip} has no monitoring configuration — it may already be retired, or it was never polled by this tenant.` };
  }
  // Partial success is reported as success WITH the failures attached: some intent was withdrawn
  // and the caller must not be told "nothing happened" when something did.
  return { ok: !failed.length, removed, failed, ip: p.ip, partial: !!(removed.length && failed.length) };
}

// Point SNMP autodiscovery at a subnet by appending a group to the existing
// discovery config (reuses its AG scanner; masked secrets on other groups preserved).
async function discoverSubnet(p: DiscoverInput) {
  if (!/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(p.subnet)) return { ok: false, error: `invalid subnet ${p.subnet} — use CIDR, e.g. 10.0.0.0/24` };
  const list: any = await (await httpClient.send({ url: DISCO_BASE, method: 'GET' })).body('json');
  const cfg = (list.items || [])[0];
  if (!cfg) return { ok: false, error: 'No autodiscovery scanner is set up yet. Autodiscovery runs on the ActiveGate — set up its scanner once, then subnets can be added from here.' };
  const groups = cfg.value?.pythonRemote?.groups || [];
  if (groups.some((g: any) => (g.addresses || []).includes(p.subnet))) return { ok: false, error: `${p.subnet} is already being scanned.` };
  const group = { addresses: [p.subnet], authentication: discoAuth(p.profileId, p.snmpVersion, p.v3), label: p.label || `wizard ${p.subnet}`, port: 161 };
  const value = { ...cfg.value, pythonRemote: { ...cfg.value.pythonRemote, groups: [...groups, group] } };
  await httpClient.send({ url: `${DISCO_BASE}/${cfg.objectId}`, method: 'PUT', body: { scope: cfg.scope, value } });
  return { ok: true, subnet: p.subnet, objectId: cfg.objectId, groups: groups.length + 1 };
}

// ── Detection layer: create the chosen anomaly detectors (settings:objects:write) ──
// The UI passes the selected detector payloads (bundled in ui/app/lib/detectors); this POSTs
// them idempotently (skips any whose title already exists). Unlike workflows, the app CAN
// create these — davis.anomaly-detectors is a settings object, covered by settings:objects:write.
const AD_SCHEMA = 'builtin:davis.anomaly-detectors';
async function createDetectors(p: { detectors: any[] }) {
  const want = Array.isArray(p.detectors) ? p.detectors : [];
  if (!want.length) return { ok: false, error: 'no detectors provided' };
  const have = new Set<string>();
  try {
    const cur: any = await (await httpClient.send({ url: `/platform/classic/environment-api/v2/settings/objects?schemaIds=${AD_SCHEMA}&fields=value&pageSize=500`, method: 'GET' })).body('json');
    for (const o of (cur.items || [])) if (o?.value?.title) have.add(o.value.title);
  } catch { /* best effort — proceed to create */ }
  const todo = want.filter((d) => !have.has(d?.value?.title));
  const skipped = want.filter((d) => have.has(d?.value?.title)).map((d) => d?.value?.title);
  if (!todo.length) return { ok: true, created: 0, skipped: skipped.length, skippedTitles: skipped, note: 'all selected detectors already present' };
  const res: any = await httpClient.send({ url: '/platform/classic/environment-api/v2/settings/objects', method: 'POST', body: todo });
  let body: any; try { body = await res.body('json'); } catch { /* ignore */ }

  // Settings v2 bulk-POST returns a 2xx envelope whose PER-OBJECT entries carry their own
  // code — individual objects can be rejected (400) while the request itself succeeds.
  // Reporting `created: todo.length` on any 2xx therefore claimed success for detectors the
  // API refused, so the operator believed alerting was armed when it was not. Count the
  // body, and surface the rejects.
  type BulkResult = { code?: number; error?: { message?: string } | string };
  type DetectorPayload = { value?: { title?: string } };
  const results: BulkResult[] = Array.isArray(body) ? (body as BulkResult[]) : [];
  const items = todo as DetectorPayload[];
  const createdTitles: (string | undefined)[] = [];
  const failed: { title?: string; code?: number; error?: string }[] = [];
  results.forEach((r, i) => {
    const title = items[i]?.value?.title;
    const code = typeof r?.code === 'number' ? r.code : undefined;
    if (code === undefined || code < 300) { createdTitles.push(title); return; }
    const err = typeof r.error === 'string' ? r.error : r.error?.message;
    failed.push({ title, code, error: err });
  });
  // No parsable per-object body (older/older-shaped responses): fall back to the old
  // behaviour rather than reporting zero, but only when the request itself succeeded.
  const created = results.length ? createdTitles.length : (res.status < 300 ? todo.length : 0);

  return {
    ok: res.status < 300 && failed.length === 0,
    status: res.status,
    created,
    createdTitles: results.length ? createdTitles : items.map((d) => d?.value?.title),
    failed,
    failedCount: failed.length,
    skipped: skipped.length,
    body,
  };
}
