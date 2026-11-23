/**
 * compliance-engine.js
 *
 * Core infrastructure for the Synology Inspector compliance checks.
 *
 * Adding a new check:
 *   Create a file in js/checks/, implement your function, then at the bottom:
 *     COMPLIANCE_CHECKS.push(myCheckFunction);
 *
 * Check function signature:
 *   function myCheck(config, tlsProfile) → Finding[]
 *
 *   config     — Map<string, string>  key-value pairs from SQLite
 *   tlsProfile — Object | null        parsed tls_profile/datastore.json
 *
 * Finding shape:
 * {
 *   id            {string}   unique, stable identifier
 *   title         {string}   short human-readable title
 *   description   {string}   longer explanation of the issue
 *   severity      {string}   'critical' | 'high' | 'medium' | 'low' | 'info'
 *   status        {string}   'fail' | 'pass' | 'unknown'
 *                            'unknown' = the setting is missing from the backup
 *                            or could not be parsed; it never affects the score
 *   category      {string}   display category
 *   frameworks    {Array}    [{code, ref, label}]
 *   affectedItems {string[]} human-readable list of affected objects
 *   remediation   {string}   concrete fix steps
 * }
 */

// ── Check registries ───────────────────────────────────────────────────────────

/** @type {Array<function(Map, Object, Object): Object[]>} */
const COMPLIANCE_CHECKS = [];

/** @type {Array<function(Map, Object, Object): Object[]>} */
const BEST_PRACTICES_CHECKS = [];

// ── Framework reference builder ────────────────────────────────────────────────

/**
 * @param {'CIS'|'NIST'|'ISO'|'NIS2'|'PCI'} code
 * @param {string} ref
 * @returns {{ code: string, ref: string, label: string }}
 */
function fwRef(code, ref) {
    return { code, ref, label: `${code} ${ref}` };
}

/**
 * Build a finding for a check whose input data is missing or unparseable.
 * Missing data must never be reported as a pass.
 *
 * @param {string}   id
 * @param {string}   name        translated, human-readable check name
 * @param {string}   category    translated category
 * @param {Object[]} frameworks
 * @returns {Object}
 */
function unknownFinding(id, name, category, frameworks) {
    return {
        id,
        title:         t('unknownTitle', name),
        description:   t('unknownDesc'),
        severity:      'info',
        status:        'unknown',
        category,
        frameworks,
        affectedItems: [],
        remediation:   '',
    };
}

// ── Account state ──────────────────────────────────────────────────────────────

/**
 * Whether a local DSM account can log in.
 * confbkp_user_tb.expire: -1 = never expires, 1 = deactivated,
 * >1 = expiry date in days since 1970-01-01 (account expires after that day).
 *
 * @param {{expire: number}} user
 * @param {Date}             [now]
 * @returns {boolean}
 */
function isAccountActive(user, now = new Date()) {
    const expire = user.expire;
    if (expire === -1) return true;
    if (expire === 1)  return false;
    if (Number.isInteger(expire) && expire > 1) {
        const todayDays = Math.floor(now.getTime() / 86400000);
        return expire >= todayDays;
    }
    return null;   // value not seen in DSM backups
}

// ── Scoring ────────────────────────────────────────────────────────────────────

const SEVERITY_PENALTY = {
    critical: 20,
    high:     10,
    medium:    5,
    low:       2,
    info:      0,
};

function calculateSecurityScore(findings) {
    const totalPenalty = findings
        .filter(f => f.status === 'fail')
        .reduce((sum, f) => sum + (SEVERITY_PENALTY[f.severity] ?? 0), 0);
    return Math.max(0, 100 - totalPenalty);
}

function scoreToGrade(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
}

function scoreToVerdict(score) {
    if (score >= 90) return t('verdictStrong');
    if (score >= 80) return t('verdictGood');
    if (score >= 70) return t('verdictAcceptable');
    if (score >= 60) return t('verdictImprove');
    if (score >= 40) return t('verdictExposure');
    return t('verdictCritical');
}

// ── Orchestrators ──────────────────────────────────────────────────────────────

/**
 * Run all security checks and return a flat array of findings.
 * The parseResult is passed as the optional third argument; existing checks
 * that only accept (config, tlsProfile) safely ignore it.
 *
 * @param {Map<string,string>} config
 * @param {Object|null}        tlsProfile
 * @param {Object}             parseResult
 * @returns {Object[]}
 */
function runAllChecks(config, tlsProfile, parseResult) {
    return COMPLIANCE_CHECKS.flatMap(fn => fn(config, tlsProfile, parseResult));
}

/**
 * Run all best-practice checks and return a flat array of findings.
 * BP findings do NOT affect the security score.
 *
 * @param {Map<string,string>} config
 * @param {Object|null}        tlsProfile
 * @param {Object}             parseResult
 * @returns {Object[]}
 */
function runAllBestPracticesChecks(config, tlsProfile, parseResult) {
    return BEST_PRACTICES_CHECKS.flatMap(fn => fn(config, tlsProfile, parseResult));
}
