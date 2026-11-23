/**
 * check-maintenance.js
 *
 * Maintenance and infrastructure security checks:
 *   1. Automatic configuration backup not configured  (medium)
 *   2. SMB signing disabled                           (medium)
 *   3. Security updates not installed automatically   (medium)
 */

function checkMaintenance(config, _tlsProfile, parseResult) {
    const findings            = [];
    const autoBackupConfigured = parseResult?.autoBackupConfigured ?? null;

    // ── Auto config backup ────────────────────────────────────────────────────
    if (autoBackupConfigured === null) {
        findings.push(unknownFinding('syn-config-backup-unknown', t('checkNameConfigBackup'),
            t('catMaintenance'), [fwRef('CIS', '11.2'), fwRef('NIST', 'CP-9'), fwRef('ISO', 'A.8.13')]));
    } else if (!autoBackupConfigured) {
        findings.push({
            id:          'syn-no-config-backup',
            title:       t('checkConfigBackupFailTitle'),
            description: t('checkConfigBackupDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catMaintenance'),
            frameworks:  [fwRef('CIS', '11.2'), fwRef('NIST', 'CP-9'), fwRef('ISO', 'A.8.13')],
            affectedItems: [],
            remediation: t('checkConfigBackupRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-config-backup-ok',
            title:       t('checkConfigBackupPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catMaintenance'),
            frameworks:  [fwRef('CIS', '11.2'), fwRef('NIST', 'CP-9')],
            affectedItems: [],
            remediation: '',
        });
    }

    // ── Automatic security updates ────────────────────────────────────────────
    // UPDATE_setting_v4.autoupdate_type: 'notify' = only notify, nothing is
    // installed automatically; 'hotfix-security' = important/security updates
    // are installed automatically (confirmed on DSM 7.x backups). Other values
    // are not verified and reported as unknown.
    const updateFw = [fwRef('CIS', '7.3'), fwRef('NIST', 'SI-2'), fwRef('ISO', 'A.8.8'), fwRef('PCI', 'Req.6.3.3')];
    let updateType = null;
    try {
        const raw = config.get('UPDATE_setting_v4');
        const type = raw ? JSON.parse(raw)?.autoupdate_type : undefined;
        if (typeof type === 'string' && type !== '') updateType = type;
    } catch (_) {}

    if (updateType !== 'notify' && updateType !== 'hotfix-security') {
        findings.push(unknownFinding('syn-security-updates-unknown', t('checkNameSecurityUpdates'),
            t('catMaintenance'), updateFw));
    } else if (updateType === 'notify') {
        findings.push({
            id:          'syn-security-updates-manual',
            title:       t('checkSecurityUpdatesFailTitle'),
            description: t('checkSecurityUpdatesDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catMaintenance'),
            frameworks:  updateFw,
            affectedItems: ['DSM'],
            remediation: t('checkSecurityUpdatesRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-security-updates-auto',
            title:       t('checkSecurityUpdatesPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catMaintenance'),
            frameworks:  updateFw,
            affectedItems: [],
            remediation: '',
        });
    }

    // ── SMB signing ───────────────────────────────────────────────────────────
    // CIFS_Enable_Server_Signing values (confirmed by inspecting live DSM backups):
    //   '0' = "Disable SMB1 signing on" (auto-negotiate, strippable by MITM) → FAIL
    //   '1' = "Client defined"                                                → FAIL
    //   '2' = "Force" (all clients must sign)                                 → PASS
    // Synology Security Advisor flags values 0 and 1 as medium-severity.
    if (config.get('CIFS_Enable_Server_Signing') !== '2') {
        findings.push({
            id:          'syn-smb-no-signing',
            title:       t('checkSMBSigningFailTitle'),
            description: t('checkSMBSigningDesc'),
            severity:    'medium',
            status:      'fail',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'SC-8'), fwRef('ISO', 'A.8.24')],
            affectedItems: ['SMB'],
            remediation: t('checkSMBSigningRemediation'),
        });
    } else {
        findings.push({
            id:          'syn-smb-signing-ok',
            title:       t('checkSMBSigningPassTitle'),
            description: '',
            severity:    'info',
            status:      'pass',
            category:    t('catProtocols'),
            frameworks:  [fwRef('CIS', '9.4'), fwRef('NIST', 'SC-8')],
            affectedItems: [],
            remediation: '',
        });
    }

    return findings;
}

COMPLIANCE_CHECKS.push(checkMaintenance);
