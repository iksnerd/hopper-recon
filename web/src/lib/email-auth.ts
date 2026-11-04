// Email-authentication analysis (SPF / DMARC / DKIM) from a domain's TXT records.
//
// "A DMARC record exists" is not the same as "this domain is protected": a
// `p=none` policy only asks receivers to report failures, so spoofed mail is
// still delivered. This module reads what each record actually says, so the
// dashboard and the report can tell those two states apart.

export type SpfAll = "-all" | "~all" | "?all" | "+all"
export type DmarcPolicy = "none" | "quarantine" | "reject"
export type Alignment = "r" | "s"

export interface SpfInfo {
  present: boolean
  /** DNS lookups the record costs, following includes. RFC 7208 allows 10. null when the engine did not report it (older scans). */
  lookups: { count: number; complete: boolean } | null
  /** More than one v=spf1 record is a permanent error (RFC 7208 §4.5): SPF fails for every message. */
  multiple: boolean
  record: string
  /** Terminating qualifier, or null when the record has none (e.g. it uses redirect=). */
  all: SpfAll | null
  includes: string[]
}

export interface DmarcInfo {
  present: boolean
  multiple: boolean
  record: string
  /** null when the record is present but p= is missing or not one of none/quarantine/reject. */
  policy: DmarcPolicy | null
  /** Subdomain policy; null means sp= is absent and subdomains inherit p. */
  subPolicy: DmarcPolicy | null
  /** Percentage of failing mail the policy applies to (default 100). */
  pct: number
  rua: string[]
  ruf: string[]
  adkim: Alignment
  aspf: Alignment
}

export interface DkimInfo {
  /** Public-key TXT records found at the selectors the engine tries. */
  keys: number
  /** Names of the selectors that answered; null when the engine did not report them (older scans). */
  selectors: string[] | null
}

/** MTA-STS, TLS-RPT and BIMI TXT records. null means the engine did not look (older scans), [] means it looked and found none. */
export interface MailPolicyInfo {
  mtaSts: string[]
  tlsRpt: string[]
  bimi: string[]
}

export interface EmailAuth {
  spf: SpfInfo
  dmarc: DmarcInfo
  dkim: DkimInfo
  mailPolicy: MailPolicyInfo | null
  /** Whether the domain has MX records, i.e. receives mail. */
  hasMx: boolean
}

/** What the engine reports beyond the TXT records; every field is absent on scans from before it existed. */
export interface EmailExtras {
  dkimSelectors?: string[]
  spfLookups?: { count: number; complete: boolean }
  mailPolicy?: MailPolicyInfo
  hasMx?: boolean
}

export type EmailSeverity = "issue" | "info" | "ok"

export interface EmailFinding {
  /** Stable across scans (the message is not: it can carry counts), so scans can be compared. */
  id: string
  severity: EmailSeverity
  area: "SPF" | "DMARC" | "DKIM" | "MTA-STS" | "TLS-RPT" | "CAA"
  /** One line, shown in the findings strip. */
  message: string
  /** Why it matters, shown in the report. */
  detail: string
}

const SPF_RE = /^\s*v=spf1(\s|$)/i
const DMARC_RE = /^\s*v=dmarc1\s*(;|$)/i
const POLICIES: readonly string[] = ["none", "quarantine", "reject"]

function asPolicy(v: string | undefined): DmarcPolicy | null {
  const s = v?.trim().toLowerCase()
  return s && POLICIES.includes(s) ? (s as DmarcPolicy) : null
}

function asAlignment(v: string | undefined): Alignment {
  return v?.trim().toLowerCase() === "s" ? "s" : "r"
}

function addresses(v: string | undefined): string[] {
  return (v ?? "").split(",").map((s) => s.trim()).filter(Boolean)
}

function parseSpf(txt: string[], lookups: EmailExtras["spfLookups"]): SpfInfo {
  const records = txt.filter((t) => SPF_RE.test(t))
  const record = records[0] ?? ""
  const all = /(?:^|\s)([+\-~?]?)all(?:\s|$)/i.exec(record)
  const qualifier = all ? (all[1] || "+") : null
  return {
    present: records.length > 0,
    lookups: records.length > 0 && lookups ? lookups : null,
    multiple: records.length > 1,
    record,
    all: qualifier ? (`${qualifier}all` as SpfAll) : null,
    includes: [...record.matchAll(/include:(\S+)/gi)].map((m) => m[1]),
  }
}

function parseDmarc(txt: string[]): DmarcInfo {
  const records = txt.filter((t) => DMARC_RE.test(t))
  const record = records[0] ?? ""
  const tags: Record<string, string> = {}
  for (const part of record.split(";")) {
    const eq = part.indexOf("=")
    if (eq > 0) tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim()
  }
  const pct = Number.parseInt(tags.pct ?? "", 10)
  return {
    present: records.length > 0,
    multiple: records.length > 1,
    record,
    policy: asPolicy(tags.p),
    subPolicy: asPolicy(tags.sp),
    pct: Number.isFinite(pct) ? Math.min(100, Math.max(0, pct)) : 100,
    rua: addresses(tags.rua),
    ruf: addresses(tags.ruf),
    adkim: asAlignment(tags.adkim),
    aspf: asAlignment(tags.aspf),
  }
}

// The engine merges TXT answers from a list of common DKIM selectors into the
// apex result without recording which selector each came from, and CNAME-hosted
// keys (e.g. a mail provider's) come back without a `v=DKIM1` tag. So count
// records that carry a public key rather than looking for the version tag.
function countDkimKeys(txt: string[]): number {
  return txt.filter((t) => /(?:^|;)\s*p=[A-Za-z0-9+/=\s]{80,}/.test(t) && /\bk=(rsa|ed25519)\b|v=dkim1/i.test(t)).length
}

export function parseEmailAuth(txt: string[], extras: EmailExtras = {}): EmailAuth {
  return {
    spf: parseSpf(txt, extras.spfLookups),
    dmarc: parseDmarc(txt),
    dkim: { keys: countDkimKeys(txt), selectors: extras.dkimSelectors ?? null },
    mailPolicy: extras.mailPolicy ?? null,
    hasMx: extras.hasMx ?? false,
  }
}

/** True only when the DMARC policy actually instructs receivers to act on failures. */
export function dmarcEnforces(d: DmarcInfo): boolean {
  return d.present && (d.policy === "quarantine" || d.policy === "reject") && d.pct > 0
}

export interface EmailBadge {
  key: "SPF" | "DMARC" | "DKIM"
  /** Shown on the badge, includes the actual setting, e.g. "DMARC p=none". */
  label: string
  /** Green only when the record does its job, not merely when it exists. */
  ok: boolean
}

/**
 * Badge states for the dashboard and history views. SPF softfail (~all) is
 * accepted only when DMARC enforces, because then DMARC decides the outcome.
 */
export function emailBadges(e: EmailAuth): EmailBadge[] {
  const { spf, dmarc, dkim } = e
  const enforcing = dmarcEnforces(dmarc)
  const overLimit = (spf.lookups?.count ?? 0) > 10
  const spfOk = spf.present && !spf.multiple && !overLimit && (spf.all === "-all" || (spf.all === "~all" && enforcing))
  const dmarcOk = !dmarc.multiple && enforcing && dmarc.pct === 100
  let dmarcLabel = "DMARC"
  if (dmarc.multiple) dmarcLabel = "DMARC (duplicate)"
  else if (dmarc.present) dmarcLabel = `DMARC ${dmarc.policy ? `p=${dmarc.policy}` : "(no p=)"}${dmarc.policy && dmarc.pct < 100 ? ` ${dmarc.pct}%` : ""}`
  return [
    { key: "SPF", label: spf.multiple ? "SPF (duplicate)" : `${spf.all ? `SPF ${spf.all}` : "SPF"}${overLimit ? ` ${spf.lookups?.count} lookups` : ""}`, ok: spfOk },
    { key: "DMARC", label: dmarcLabel, ok: dmarcOk },
    { key: "DKIM", label: "DKIM", ok: dkim.keys > 0 },
  ]
}

export function assessEmailAuth(e: EmailAuth): EmailFinding[] {
  const out: EmailFinding[] = []
  const { spf, dmarc, dkim } = e

  // SPF
  if (!spf.present) {
    out.push({ id: "spf-missing", severity: "issue", area: "SPF", message: "No SPF record — receivers have no list of servers allowed to send as this domain",
      detail: "SPF publishes the mail servers allowed to send for the domain. Without it, receivers cannot check the sending server, and DMARC has one fewer way to pass." })
  } else if (spf.multiple) {
    out.push({ id: "spf-multiple", severity: "issue", area: "SPF", message: "More than one SPF record — SPF fails for every message",
      detail: "A domain must publish exactly one v=spf1 record. Two or more is a permanent error (RFC 7208 §4.5), so receivers treat SPF as failed for all mail, including legitimate mail. Merge them into one record." })
  } else if (spf.all === "+all" || spf.all === "?all") {
    out.push({ id: "spf-open", severity: "issue", area: "SPF", message: `SPF ends in ${spf.all} — it does not restrict who can send`,
      detail: spf.all === "+all"
        ? "+all authorises every server on the internet to send as this domain, which makes the record worthless."
        : "?all (neutral) tells receivers to make no judgement about servers that are not listed, so unlisted senders are not marked." })
  } else if (spf.all === "~all") {
    out.push({ id: "spf-softfail", severity: "info", area: "SPF", message: "SPF ends in ~all (softfail) — unlisted senders are marked suspicious, not rejected",
      detail: "Softfail asks receivers to treat mail from unlisted servers as suspicious, which most deliver anyway. On its own it does not stop spoofing; DMARC enforcement is what turns a failed check into a quarantined or rejected message. Move to -all once DMARC enforces." })
  } else if (spf.all === "-all") {
    out.push({ id: "spf-hardfail", severity: "ok", area: "SPF", message: "SPF ends in -all (hard fail) — unlisted senders fail the check",
      detail: "Mail from servers not in the record fails SPF." })
  } else {
    out.push({ id: "spf-no-all", severity: "info", area: "SPF", message: "SPF has no terminating all — unlisted senders are not addressed",
      detail: "The record does not end in an all mechanism (it may delegate with redirect=). Servers that are not listed get a neutral result." })
  }

  if (spf.present && !spf.multiple && spf.lookups) {
    const { count, complete } = spf.lookups
    const shown = complete ? `${count}` : `at least ${count}`
    if (count > 10) {
      out.push({ id: "spf-lookups-over", severity: "issue", area: "SPF", message: `SPF needs ${shown} DNS lookups, over the limit of 10 — SPF fails for every message`,
        detail: "RFC 7208 allows at most 10 DNS lookups while evaluating SPF (each include, a, mx, ptr, exists and redirect counts, including those inside included records). Past that, receivers return a permanent error and treat SPF as failed for all mail, legitimate mail included. Remove includes for services that no longer send mail, or flatten them." })
    } else if (count === 10) {
      out.push({ id: "spf-lookups-limit", severity: "info", area: "SPF", message: "SPF is at the limit of 10 DNS lookups — one more include breaks it",
        detail: "Adding another sending service that uses include: pushes SPF over RFC 7208's limit of 10 lookups, after which it fails for every message." })
    } else if (!complete) {
      out.push({ id: "spf-lookups-incomplete", severity: "info", area: "SPF", message: `SPF uses at least ${count} DNS lookups — an included record could not be fetched`,
        detail: "The engine could not resolve every include, so the true count may be higher. Re-run the scan, and check the included domains still publish an SPF record." })
    }
  }

  // DMARC
  if (!dmarc.present) {
    out.push({ id: "dmarc-missing", severity: "issue", area: "DMARC", message: "No DMARC record — mail that fails SPF and DKIM is still delivered",
      detail: "DMARC tells receivers what to do with mail that fails SPF/DKIM alignment, and sends the domain owner reports. Without it, anyone can send mail that claims to be from this domain and receivers decide for themselves." })
  } else if (dmarc.multiple) {
    out.push({ id: "dmarc-multiple", severity: "issue", area: "DMARC", message: "More than one DMARC record — receivers ignore them all",
      detail: "Receivers discard DMARC when _dmarc publishes more than one v=DMARC1 record, so the domain behaves as if it had none. Delete all but one." })
  } else if (dmarc.policy === null) {
    out.push({ id: "dmarc-invalid", severity: "issue", area: "DMARC", message: "DMARC record has no valid p= policy — receivers cannot apply it",
      detail: "p= is required and must be none, quarantine or reject. Without a valid value the record does nothing." })
  } else if (dmarc.policy === "none") {
    out.push({ id: "dmarc-none", severity: "issue", area: "DMARC", message: "DMARC is p=none (monitor only) — spoofed mail is still delivered",
      detail: "p=none asks receivers to send reports and otherwise treat failing mail normally. A message that forges this domain and fails SPF and DKIM reaches the inbox. It is the right first step while finding legitimate senders, but it gives no protection against spoofing." })
  } else if (dmarc.pct < 100) {
    out.push({ id: "dmarc-partial", severity: "info", area: "DMARC", message: `DMARC p=${dmarc.policy} applies to only ${dmarc.pct}% of failing mail`,
      detail: `pct=${dmarc.pct} means the other ${100 - dmarc.pct}% of failing mail is treated as if the policy were one step weaker. Raise pct to 100 once reports show no legitimate mail failing.` })
  } else {
    out.push({ id: "dmarc-enforcing", severity: "ok", area: "DMARC", message: `DMARC p=${dmarc.policy} — failing mail is ${dmarc.policy === "reject" ? "rejected" : "quarantined"}`,
      detail: dmarc.policy === "reject" ? "Receivers are told to refuse mail that fails DMARC." : "Receivers are told to treat mail that fails DMARC as spam. p=reject is the strongest setting once reports are clean." })
  }
  if (dmarc.present && !dmarc.multiple && dmarc.policy !== null && dmarc.rua.length === 0) {
    out.push({ id: "dmarc-no-rua", severity: "info", area: "DMARC", message: "No rua= address — no aggregate reports are received",
      detail: "Aggregate reports list every server sending as the domain and whether it passed. Without rua= there is no way to find legitimate senders before enforcing, or to see spoofing attempts." })
  }
  if (dmarcEnforces(dmarc) && dmarc.subPolicy === "none") {
    out.push({ id: "dmarc-sp-none", severity: "issue", area: "DMARC", message: "DMARC sp=none leaves subdomains unprotected",
      detail: "The domain enforces DMARC but sp=none exempts subdomains, so anything@sub.example.com can still be spoofed." })
  }

  // DKIM
  if (dkim.keys === 0) {
    out.push({ id: "dkim-none", severity: "info", area: "DKIM", message: "No DKIM keys found at common selectors — this scan checks a short list only",
      detail: "The engine queries a fixed list of common selectors. A sender using another selector will not appear here, so this is not proof that no mail is signed. The DMARC aggregate reports show the selectors actually in use." })
  } else {
    const named = dkim.selectors && dkim.selectors.length > 0 ? ` (selectors: ${dkim.selectors.join(", ")})` : ""
    out.push({ id: "dkim-ok", severity: "ok", area: "DKIM", message: `${dkim.keys} DKIM public key${dkim.keys === 1 ? "" : "s"} published at common selectors${named}`,
      detail: "Receivers can verify signatures made with these keys. Only a fixed list of common selectors is checked, so other selectors may exist." })
  }

  // MTA-STS / TLS-RPT: only meaningful for a domain that receives mail.
  if (e.mailPolicy && e.hasMx) {
    const { mtaSts, tlsRpt } = e.mailPolicy
    if (mtaSts.length === 0) {
      out.push({ id: "mta-sts-missing", severity: "info", area: "MTA-STS", message: "No MTA-STS policy — mail sent to this domain can be downgraded to plaintext",
        detail: "MTA-STS tells sending servers to require TLS and to deliver only to the listed mail servers. Without it, an attacker on the network path can strip encryption from inbound mail by interfering with STARTTLS." })
    } else if (tlsRpt.length === 0) {
      out.push({ id: "tls-rpt-missing", severity: "info", area: "TLS-RPT", message: "MTA-STS is published but no TLS-RPT — delivery failures go unreported",
        detail: "TLS-RPT (_smtp._tls) asks senders to report TLS and MTA-STS failures, which is how a broken policy or a downgrade attempt becomes visible." })
    } else {
      out.push({ id: "mta-sts-ok", severity: "ok", area: "MTA-STS", message: "MTA-STS and TLS-RPT are published",
        detail: "Senders are told to require TLS for inbound mail and to report failures." })
    }
  }

  return out
}

/** CAA records (the issuers allowed to sign certificates). null means the engine did not report them (older scans). */
export function assessCaa(caa: string[] | null): EmailFinding[] {
  if (caa === null) return []
  if (caa.length === 0) {
    return [{ id: "caa-none", severity: "info", area: "CAA", message: "No CAA records — any certificate authority may issue certificates for this domain",
      detail: "CAA records limit which certificate authorities may issue for the domain. Without them, a mis-issued or fraudulently obtained certificate from any CA is accepted by browsers." }]
  }
  return [{ id: "caa-ok", severity: "ok", area: "CAA", message: `CAA limits certificate issuance to: ${caa.join(", ")}`,
    detail: "Only the listed certificate authorities should issue certificates for this domain." }]
}

/**
 * The DMARC record to publish next, or null when the current one needs no
 * change. Keeps the reporting addresses and alignment the domain already chose.
 * Moving from p=none to quarantine can send legitimate mail from an
 * unrecognised sender to spam, so check aggregate reports first.
 */
export function suggestDmarc(domain: string, d: DmarcInfo): string | null {
  if (d.multiple) return null
  if (!d.present || d.policy === null) return `v=DMARC1; p=none; rua=mailto:dmarc@${domain};`
  if (d.policy !== "none" && d.pct >= 100) return null
  const tags = [`v=DMARC1`, `p=${d.policy === "none" ? "quarantine" : d.policy}`]
  if (d.subPolicy) tags.push(`sp=${d.subPolicy === "none" ? "quarantine" : d.subPolicy}`)
  if (d.rua.length) tags.push(`rua=${d.rua.join(",")}`)
  if (d.ruf.length) tags.push(`ruf=${d.ruf.join(",")}`)
  if (d.adkim === "s") tags.push("adkim=s")
  if (d.aspf === "s") tags.push("aspf=s")
  return tags.join("; ") + ";"
}
