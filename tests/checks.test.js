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
});

test('missing data is reported as unknown, never as passed', () => {
    const app = loadApp();
    const findings = runChecks(app, {}, { autoBackupConfigured: null });
    const unknown = [...findings.filter(f => f.status === 'unknown').map(f => f.id)].sort();
    assert.deepEqual(unknown, [
        'syn-admin-unknown', 'syn-admins-unknown', 'syn-config-backup-unknown', 'syn-csrf-unknown',
        'syn-dos-unknown', 'syn-firewall-unknown', 'syn-guest-unknown', 'syn-iframe-unknown',
        'syn-ip-check-unknown', 'syn-qc-unknown', 'syn-security-updates-unknown', 'syn-smb1-unknown',
        'syn-tls-unknown',
    ]);
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
    assert.deepEqual(run('all'), ['bp-update-auto:fail', 'syn-security-updates-auto:pass']);
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

test('every translation key used by the checks is defined', () => {
    const app = loadApp('de');
    const dir = path.join(ROOT, 'js/checks');
    const used = new Set();
    for (const file of fs.readdirSync(dir)) {
        const src = fs.readFileSync(path.join(dir, file), 'utf8');
        for (const m of src.matchAll(/\bt\('(\w+)'/g)) used.add(m[1]);
    }
    assert.deepEqual([...used].filter(k => app.t(k) === k), []);
});
