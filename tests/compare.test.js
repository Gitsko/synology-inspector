'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const { loadApp } = require('./load-app.js');

// Values created inside the vm context have their own Array/Object prototypes.
const plain = v => JSON.parse(JSON.stringify(v));

function diff(a, b) {
    const app = loadApp();
    return plain(app.diffConfigMaps(new Map(Object.entries(a)), new Map(Object.entries(b))));
}

const byKey = entries => Object.fromEntries(entries.map(e => [e.key, e]));

test('classifies keys as only in A, only in B, changed or same', () => {
    const result = byKey(diff(
        { FTP_isEnableFTP: '1', SNMP_isEnableSNMP: '0', AFP_isEnableAFP: '0' },
        { FTP_isEnableFTP: '0', SNMP_isEnableSNMP: '0', NFS_isEnableNFS: '1' },
    ));
    assert.equal(result.FTP_isEnableFTP.status, 'changed');
    assert.equal(result.SNMP_isEnableSNMP.status, 'same');
    assert.equal(result.AFP_isEnableAFP.status, 'onlyA');
    assert.equal(result.NFS_isEnableNFS.status, 'onlyB');
});

test('returns entries sorted by key', () => {
    const keys = diff({ b: '1', a: '1' }, { c: '1' }).map(e => e.key);
    assert.deepEqual(keys, ['a', 'b', 'c']);
});

test('treats unreadable values as not comparable, never as equal', () => {
    const result = byKey(diff(
        { X_both_null: null, X_one_null: null, X_only_a_null: null },
        { X_both_null: null, X_one_null: '1' },
    ));
    assert.equal(result.X_both_null.status, 'unknown');
    assert.equal(result.X_one_null.status, 'unknown');
    assert.equal(result.X_only_a_null.status, 'onlyA');
});

test('shows short values of harmless keys', () => {
    const [entry] = diff({ Terminal_SSHPort: '22' }, { Terminal_SSHPort: '2222' });
    assert.equal(entry.a, '22');
    assert.equal(entry.b, '2222');
});

test('never shows values of secret-like keys', () => {
    const secretKeys = ['Ad_passwd', 'LDAP_szPasswd', 'NOTIFY_smtpconf', 'retain_admin_pwd',
        'SOME_api_token', 'SOME_secret', 'SOME_prikey', 'NOTIFY_mailfrom', 'SOME_cert',
        'NetBKP_PairID'];
    const a = Object.fromEntries(secretKeys.map(k => [k, 'x']));
    const b = Object.fromEntries(secretKeys.map(k => [k, 'y']));
    for (const entry of diff(a, b)) {
        assert.equal(entry.status, 'changed', entry.key);
        assert.equal(entry.a, null, entry.key);
        assert.equal(entry.b, null, entry.key);
    }
});

test('never shows long values, whatever the key', () => {
    const long = 'x'.repeat(33);
    const [entry] = diff({ FIREWALL_config: long }, { FIREWALL_config: long + 'y' });
    assert.equal(entry.status, 'changed');
    assert.equal(entry.a, null);
    assert.equal(entry.b, null);
});

test('hides a value on one side only when only that side is unsafe', () => {
    const [entry] = diff({ w3_server_header: 'nginx' }, { w3_server_header: 'y'.repeat(40) });
    assert.equal(entry.a, 'nginx');
    assert.equal(entry.b, null);
});
