'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('node:fs');
const path   = require('node:path');
const { loadApp, runChecks, ROOT } = require('./load-app.js');

const DAY = 86400000;
const today = () => Math.floor(Date.now() / DAY);

function byId(findings, id) {
    return findings.find(f => f.id === id);
}

function ids(findings) {
    return findings.map(f => f.id);
}

test('isAccountActive interprets the expire column', () => {
    const app = loadApp();
    assert.equal(app.isAccountActive({ expire: -1 }), true);
    assert.equal(app.isAccountActive({ expire: 1 }), false);
    assert.equal(app.isAccountActive({ expire: today() + 30 }), true);
    assert.equal(app.isAccountActive({ expire: today() - 30 }), false);
    for (const expire of [0, -2, null, undefined, NaN, 1.5]) {
        assert.equal(app.isAccountActive({ expire }), null, String(expire));
    }
});

test('account with an unrecognized expire value is unknown, not active', () => {
    const app = loadApp();
    const odd = runChecks(app, {}, { users: [
        { name: 'admin', uid: 1024, expire: 0 },
        { name: 'guest', uid: 1025, expire: null },
        { name: 'alice', uid: 1026, expire: -1 },
    ], adminMembers: ['admin', 'alice'] });
    for (const id of ['syn-admin-unknown', 'syn-guest-unknown', 'syn-admins-unknown']) assert.ok(ids(odd).includes(id), id);

    const users = ['a', 'b', 'c'].map((name, i) => ({ name, uid: 1030 + i, expire: -1 }));
    users.push({ name: 'd', uid: 1040, expire: 0 });
    const many = runChecks(app, {}, { users, adminMembers: ['a', 'b', 'c', 'd'] });
    assert.equal(byId(many, 'syn-admins-many').status, 'fail');
});

test('missing data is reported as unknown, never as passed', () => {
    const app = loadApp();
    const findings = runChecks(app, {}, { autoBackupConfigured: null });
    const unknown = [...findings.filter(f => f.status === 'unknown').map(f => f.id)].sort();
    assert.deepEqual(unknown, [
        'syn-account-protection-unknown', 'syn-admin-unknown', 'syn-admins-unknown', 'syn-advisories-unknown', 'syn-config-backup-unknown', 'syn-csrf-unknown',
        'syn-dos-unknown', 'syn-firewall-unknown', 'syn-guest-unknown', 'syn-iframe-unknown',
        'syn-ip-check-unknown', 'syn-notify-unknown', 'syn-ntlmv1-unknown', 'syn-qc-unknown', 'syn-security-updates-unknown',
        'syn-services-unknown', 'syn-smb1-unknown', 'syn-ssh-unknown', 'syn-telnet-unknown', 'syn-tls-unknown',
    ]);
});

test('settings verified in real backups pass only with their explicit value', () => {
    const app = loadApp();
    const passes = runChecks(app, {}, { autoBackupConfigured: null }).filter(f => f.status === 'pass').map(f => f.id);
    for (const id of ['syn-ssh-disabled', 'syn-telnet-disabled', 'syn-ntlmv1-disabled', 'syn-guest-disabled', 'syn-admins-ok']) {
        assert.ok(!passes.includes(id), `${id} must not pass without data`);
    }
    const off = runChecks(app, { Terminal_isEnableSSH: '0', Terminal_isEnableTelnet: '0', CIFS_Enable_NTLMv1_Auth: '0' });
    for (const id of ['syn-ssh-disabled', 'syn-telnet-disabled', 'syn-ntlmv1-disabled']) assert.ok(ids(off).includes(id), id);
});

test('missing guest row or no active administrator is unknown', () => {
    const app = loadApp();
    const users = [{ name: 'alice', uid: 1026, expire: -1 }];
    assert.ok(ids(runChecks(app, {}, { users })).includes('syn-guest-unknown'));
    const inactive = runChecks(app, {}, { users: [{ name: 'admin', uid: 1024, expire: 1 }], adminMembers: ['admin'] });
    assert.ok(ids(inactive).includes('syn-admins-unknown'));
});

test('unknown findings do not change the score', () => {
    const app = loadApp();
    const fail = { id: 'x', status: 'fail', severity: 'high' };
    const unknown = { id: 'y', status: 'unknown', severity: 'info' };
    assert.equal(app.calculateSecurityScore([fail, unknown]), app.calculateSecurityScore([fail]));
});

test('active default admin fails, deactivated admin passes', () => {
    const app = loadApp();
    const active = runChecks(app, {}, { users: [{ name: 'admin', uid: 1024, expire: -1 }] });
    assert.equal(byId(active, 'syn-admin-active').status, 'fail');
    const off = runChecks(app, {}, { users: [{ name: 'admin', uid: 1024, expire: 1 }] });
    assert.equal(byId(off, 'syn-admin-disabled').status, 'pass');
    assert.ok(!ids(off).includes('syn-admin-active'));
});

test('active guest account fails, with shares raising the severity', () => {
    const app = loadApp();
    const users = [{ name: 'guest', uid: 1025, expire: -1 }];
    const noShares = byId(runChecks(app, {}, { users }), 'syn-guest-active');
    assert.equal(noShares.severity, 'medium');

    const sharePrivileges = [
        { share: 'public', type: 'user', name: 'guest', privilege: 'RW' },
        { share: 'media',  type: 'user', name: 'guest', privilege: 'Deny' },
        { share: 'docs',   type: 'user', name: 'bob',   privilege: 'RO' },
    ];
    const withShares = byId(runChecks(app, {}, { users, sharePrivileges }), 'syn-guest-active');
    assert.equal(withShares.severity, 'high');
    assert.deepEqual([...withShares.affectedItems], ['public (RW)']);

    const disabled = runChecks(app, {}, { users: [{ name: 'guest', uid: 1025, expire: 1 }], sharePrivileges });
    assert.equal(byId(disabled, 'syn-guest-disabled').status, 'pass');
});

test('more than two active administrators fail; inactive and service members are skipped', () => {
    const app = loadApp();
    const users = [
        { name: 'admin', uid: 1024, expire: 1 },
        { name: 'alice', uid: 1026, expire: -1 },
        { name: 'bob',   uid: 1027, expire: -1 },
        { name: 'carol', uid: 1028, expire: today() - 1 },
    ];
    const ok = runChecks(app, {}, { users, adminMembers: ['admin', 'alice', 'bob', 'carol', 'SomePackage'] });
    assert.equal(byId(ok, 'syn-admins-ok').status, 'pass');

    users.push({ name: 'dave', uid: 1029, expire: -1 });
    const many = byId(runChecks(app, {}, { users, adminMembers: ['alice', 'bob', 'dave'] }), 'syn-admins-many');
    assert.equal(many.status, 'fail');
    assert.deepEqual([...many.affectedItems], ['alice', 'bob', 'dave']);
});

test('firewall status is read from FIREWALL_config', () => {
    const app = loadApp();
    const cfg = status => ({ FIREWALL_config: JSON.stringify({ config_firewall_settings: { profile: 'custom', status } }) });
    assert.ok(ids(runChecks(app, cfg(false))).includes('syn-firewall-off'));
    assert.ok(ids(runChecks(app, cfg(true))).includes('syn-firewall-on'));
    assert.ok(ids(runChecks(app, { FIREWALL_config: 'not json' })).includes('syn-firewall-unknown'));
});

test('TLS check flags outdated protocols and ignores temp copies', () => {
    const app = loadApp();
    const conf = protocols => `ssl_protocols               ${protocols};\nssl_ciphers X;\n`;
    const weak = runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/dsm.conf', text: conf('TLSv1 TLSv1.1 TLSv1.2') },
        { name: 'ConfigBkp/tls_profile/config/system_quickconnect.conf', text: conf('TLSv1.2 TLSv1.3') },
        { name: 'ConfigBkp/tls_profile/config/temp-dsm.conf.Ab12Cd', text: conf('SSLv3') },
    ] });
    assert.deepEqual([...byId(weak, 'syn-tls-weak').affectedItems], ['dsm (TLSv1, TLSv1.1)']);

    const strong = runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/dsm.conf', text: conf('TLSv1.2 TLSv1.3') },
        { name: 'ConfigBkp/tls_profile/config/temp-dsm.conf.Ab12Cd', text: conf('TLSv1') },
    ] });
    assert.ok(ids(strong).includes('syn-tls-ok'));

    const twoServers = runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/dsm.conf', text: conf('TLSv1.2') + conf('TLSv1 TLSv1.2') },
    ] });
    assert.deepEqual([...byId(twoServers, 'syn-tls-weak').affectedItems], ['dsm (TLSv1)']);

    const noDirective = runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/LogCenter.conf', text: 'ssl_certificate x;\n' },
    ] });
    assert.ok(ids(noDirective).includes('syn-tls-unknown'));
});

test('update settings: security check and best practice agree on hotfix-security', () => {
    const app = loadApp();
    const run = type => {
        const config = new Map([['UPDATE_setting_v4', JSON.stringify({ autoupdate_type: type })]]);
        const pr = { config, users: [], adminMembers: [], schedulerTasks: [], autoBackupConfigured: true, hasBtrfs: false };
        return [...app.runAllChecks(config, null, pr), ...app.runAllBestPracticesChecks(config, null, pr)]
            .filter(f => f.id.includes('update'))
            .map(f => `${f.id}:${f.status}`)
            .sort();
    };
    assert.deepEqual(run('notify'), ['bp-update-notify-ok:pass', 'syn-security-updates-manual:fail']);
    assert.deepEqual(run('hotfix-security'), ['bp-update-notify-ok:pass', 'syn-security-updates-auto:pass']);
    assert.deepEqual(run('all'), ['bp-update-auto:fail', 'syn-security-updates-unknown:unknown']);
});

test('non-string update type is unknown, not a pass', () => {
    const app = loadApp();
    const findings = runChecks(app, { UPDATE_setting_v4: JSON.stringify({ autoupdate_type: true }) });
    assert.ok(ids(findings).includes('syn-security-updates-unknown'));
});

test('unrecognized SMB minimum protocol is unknown, not a pass', () => {
    const app = loadApp();
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'typo' })).includes('syn-smb1-unknown'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB2' })).includes('syn-smb1-disabled'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'NT1' })).includes('syn-smb1-enabled'));
});

test('anonymous FTP is only reported while FTP is enabled', () => {
    const app = loadApp();
    const anonId = f => f.filter(x => x.id.includes('ftp-anon') && x.status === 'fail');
    assert.equal(anonId(runChecks(app, { FTP_isEnableFTP: '0', FTP_isEnableAnon: '1' })).length, 0);
    assert.equal(anonId(runChecks(app, { FTP_isEnableFTP: '1', FTP_isEnableAnon: '1' })).length, 1);
});

test('password checks reference password controls, not lockout controls', () => {
    const app = loadApp();
    const findings = runChecks(app, {});
    const labels = findings.filter(f => f.id.startsWith('syn-pwd')).flatMap(f => f.frameworks.map(r => r.label));
    assert.ok(labels.length > 0);
    for (const lockout of ['CIS 4.10', 'NIST AC-7', 'PCI Req.8.3.4']) {
        assert.ok(!labels.includes(lockout), `${lockout} must not be used for password checks`);
    }
});

test('every i18n key exists in English and German', () => {
    const src = fs.readFileSync(path.join(ROOT, 'js/i18n.js'), 'utf8');
    const [enPart, dePart] = src.split(/\n {8}de: \{/);
    const keys = part => new Set([...part.matchAll(/^ {12}(\w+):/gm)].map(m => m[1]));
    const en = keys(enPart);
    const de = keys(dePart);
    assert.deepEqual([...en].filter(k => !de.has(k)), []);
    assert.deepEqual([...de].filter(k => !en.has(k)), []);
});

test('every translation key used by the checks and views is defined', () => {
    const app = loadApp('de');
    const dir = path.join(ROOT, 'js/checks');
    const files = [...fs.readdirSync(dir).map(f => path.join(dir, f)),
        ...['compliance-engine.js', 'compliance-view.js', 'bestpractices-view.js', 'app.js']
            .map(f => path.join(ROOT, 'js', f))];
    const used = new Set();
    for (const file of files) {
        const src = fs.readFileSync(file, 'utf8');
        for (const m of src.matchAll(/\bt\('(\w+)'\s*[,)]/g)) used.add(m[1]);
    }
    assert.deepEqual([...used].filter(k => app.t(k) === k), []);
});

test('advisory status follows the fixed releases per DSM branch', () => {
    const app = loadApp();
    const adv = { fixes: [
        { build: 69057, update: null, version: null },
        { build: 86009, update: 6, version: '7.3.2-86009-6' },
        { build: 90080, update: 2, version: '7.4.1-90080-2' },
    ] };
    const status = build => app.dsmAdvisoryStatus(build, adv).status;
    assert.equal(status(42962), 'unknown');      // branch not listed
    assert.equal(status(69057), 'vulnerable');   // no fix for this branch
    assert.equal(status(72806), 'vulnerable');   // between listed branches
    assert.equal(status(86003), 'vulnerable');
    assert.equal(app.dsmAdvisoryStatus(86003, adv).version, '7.3.2-86009-6');
    assert.equal(status(86009), 'unknown');      // fixed by an update of the same build
    assert.equal(status(90081), 'fixed');        // newer than every fix
    assert.equal(app.dsmAdvisoryStatus(90075, { fixes: [{ build: 90075, update: 0, version: '7.4-90075' }] }).status, 'fixed');
});

test('advisory check: vulnerable build fails, own build with pending update is unknown', () => {
    const app = loadApp();
    const run = (build, cfg = {}) => runChecks(app, cfg, { info: { dsm_buildnumber: String(build) } });
    const old = byId(run(86003, { w3_runHTTP2: 'yes' }), 'syn-advisories-vulnerable');
    assert.equal(old.severity, 'critical');
    assert.ok(old.affectedItems.some(i => i.startsWith('SA-26:20') && i.includes('HTTP/2')));
    const current = byId(run(90080), 'syn-advisories-unknown');
    assert.equal(current.status, 'unknown');
    assert.deepEqual([...current.affectedItems].map(i => i.split(' ')[0]), ['SA-26:21', 'SA-26:20', 'SA-26:19']);
    assert.ok(ids(run(90100)).includes('syn-advisories-ok'));
});

test('advisory check keeps unverifiable advisories next to vulnerable ones', () => {
    const app = loadApp();
    const findings = runChecks(app, {}, { info: { dsm_buildnumber: '69057' } });
    const vuln = byId(findings, 'syn-advisories-vulnerable');
    const unk  = byId(findings, 'syn-advisories-unknown');
    assert.deepEqual([...vuln.affectedItems].map(i => i.split(' ')[0]), ['SA-26:21', 'SA-26:20']);
    assert.ok(unk, 'unknown advisories must not be dropped');
    assert.deepEqual([...unk.affectedItems].map(i => i.split(' ')[0]), ['SA-26:19', 'SA-26:13']);
});

test('advisory check rejects build numbers with trailing garbage', () => {
    const app = loadApp();
    const f = byId(runChecks(app, {}, { info: { dsm_buildnumber: '90100-invalid' } }), 'syn-advisories-unknown');
    assert.ok(f);
    assert.equal(f.affectedItems.length, 0);
});

test('session IP binding needs an explicit boolean', () => {
    const app = loadApp();
    const sec = data => ({ SECURITY_: JSON.stringify([{ api: 'SYNO.Core.Security.DSM', result: { data } }]) });
    assert.ok(ids(runChecks(app, sec({ skip_ip_checking: false }))).includes('syn-ip-check-on'));
    assert.ok(ids(runChecks(app, sec({ skip_ip_checking: true }))).includes('syn-ip-check-off'));
    assert.ok(ids(runChecks(app, sec({}))).includes('syn-ip-check-unknown'));
    assert.ok(ids(runChecks(app, sec({ skip_ip_checking: 'false' }))).includes('syn-ip-check-unknown'));
});

test('a non-numeric minimum password length is unknown, not a pass', () => {
    const app = loadApp();
    const cfg = len => ({ Passwdstrength_isApplyPasswdRule: '1', Passwdstrength_isEnableMinLength: '1', Passwdstrength_minLength: len });
    assert.ok(ids(runChecks(app, cfg('abc'))).includes('syn-pwd-length-unknown'));
    assert.ok(ids(runChecks(app, cfg('12'))).includes('syn-pwd-length-ok'));
    assert.ok(ids(runChecks(app, cfg('8'))).includes('syn-pwd-length-weak'));
});

test('DoS protection reads only an active directive per interface', () => {
    const app = loadApp();
    const dos = ini => ({ DOS_config: JSON.stringify({ '/etc/fw_security/eth0.conf': ini }) });
    assert.ok(ids(runChecks(app, dos('\n[SETTINGS]\ndos_protect_enable=yes\n'))).includes('syn-dos-protected'));
    assert.ok(ids(runChecks(app, dos('[SETTINGS]\n#dos_protect_enable=yes\ndos_protect_enable=no\n'))).includes('syn-dos-incomplete'));
    assert.ok(ids(runChecks(app, dos('[SETTINGS]\n# dos_protect_enable=yes\n'))).includes('syn-dos-incomplete'));
    assert.ok(ids(runChecks(app, dos('[SETTINGS]\ndos_protect_enable=yesterday\n'))).includes('syn-dos-incomplete'));
});

test('TLS snippets with unrecognized protocol names are not a pass', () => {
    const app = loadApp();
    const conf = protocols => `ssl_protocols ${protocols};\n`;
    const run = text => runChecks(app, {}, { tlsConfigs: [
        { name: 'ConfigBkp/tls_profile/config/dsm.conf', text: conf('TLSv1.2 TLSv1.3') },
        { name: 'ConfigBkp/tls_profile/config/webdav.conf', text },
    ] });
    assert.ok(ids(run(conf('UNKNOWN'))).includes('syn-tls-unknown'));
    assert.ok(ids(run(conf('UNKNOWN TLSv1'))).includes('syn-tls-weak'));
    assert.ok(ids(run(conf('TLSv1.2'))).includes('syn-tls-ok'));
});

test('SMB minimum protocol accepts only real SMB2/SMB3 dialect names', () => {
    const app = loadApp();
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB2_10' })).includes('syn-smb1-disabled'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB3_11' })).includes('syn-smb1-disabled'));
    assert.ok(ids(runChecks(app, { CIFS_Min_Protocol: 'SMB2-invalid' })).includes('syn-smb1-unknown'));
});

test('optional services: enabled ones fail, all explicitly off passes', () => {
    const app = loadApp();
    const on = byId(runChecks(app, { NetBKP_isEnableNetBkp: '1', NFS_isEnableNFS: '1', SNMP_isEnableSNMP: '0' }), 'syn-services-enabled');
    assert.deepEqual([...on.affectedItems], ['rsync', 'NFS']);
    assert.ok(ids(runChecks(app, { NetBKP_isEnableNetBkp: '0', NFS_isEnableNFS: '0', SNMP_isEnableSNMP: '0' })).includes('syn-services-disabled'));
    assert.ok(ids(runChecks(app, { NetBKP_isEnableNetBkp: '0', NFS_isEnableNFS: '0' })).includes('syn-services-unknown'));
});

test('default ports best practice only counts SSH while it is enabled', () => {
    const app = loadApp();
    const bp = cfg => app.runAllBestPracticesChecks(new Map(Object.entries(cfg)), null, { schedulerTasks: [] });
    const fail = byId(bp({ w3_admin_port: '5000', w3_secure_admin_port: '5001', Terminal_isEnableSSH: '1', Terminal_SSHPort: '22' }), 'bp-default-ports');
    assert.deepEqual([...fail.affectedItems], ['DSM HTTP 5000', 'DSM HTTPS 5001', 'SSH 22']);
    assert.ok(ids(bp({ w3_admin_port: '5009', w3_secure_admin_port: '5010', Terminal_isEnableSSH: '0', Terminal_SSHPort: '22' })).includes('bp-custom-ports'));
});

test('notifications: one enabled channel passes, all off fails, a configured webhook is unknown', () => {
    const app = loadApp();
    const off = { NOTIFY_smtp_mail_enabled: '0', NOTIFY_pushservice_mail_enabled: '0',
        NOTIFY_pushservice_mobile_enabled: '0', NOTIFY_sms_enable: '0' };
    const find = cfg => [...runChecks(app, cfg)].filter(f => f.id.startsWith('syn-notify-')).map(f => `${f.id}:${f.status}`);
    assert.deepEqual(find(off), ['syn-notify-off:fail']);
    assert.deepEqual(find({ ...off, NOTIFY_webhookconf: 'null' }), ['syn-notify-off:fail']);
    assert.deepEqual(find({ ...off, NOTIFY_pushservice_mobile_enabled: '1' }), ['syn-notify-ok:pass']);
    assert.deepEqual(find({ NOTIFY_smtp_mail_enabled: '1' }), ['syn-notify-ok:pass']);
    assert.deepEqual(find({ ...off, NOTIFY_sms_enable: 'yes' }), ['syn-notify-unknown:unknown']);
    assert.deepEqual(find({ ...off, NOTIFY_webhookconf: '{"hooks":[{}]}' }), ['syn-notify-unknown:unknown']);
    assert.equal(byId(runChecks(app, off), 'syn-notify-off').severity, 'low');
});

test('account protection: enabled passes, disabled fails, missing is unknown', () => {
    const app = loadApp();
    const find = enabled => [...runChecks(app, {}, { accountProtectionEnabled: enabled })]
        .filter(f => f.id.startsWith('syn-account-protection-')).map(f => `${f.id}:${f.status}:${f.severity}`);
    assert.deepEqual(find(true), ['syn-account-protection-on:pass:info']);
    assert.deepEqual(find(false), ['syn-account-protection-off:fail:low']);
    assert.deepEqual(find(null), ['syn-account-protection-unknown:unknown:info']);
});
