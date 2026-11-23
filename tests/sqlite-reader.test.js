'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('node:fs');
const os     = require('node:os');
const path   = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { loadApp } = require('./load-app.js');

// Values created inside the vm context have their own Array/Object prototypes.
const plain = v => JSON.parse(JSON.stringify(v));

/**
 * Build a SQLite file with the real SQLite engine and return its bytes.
 * A small page size forces overflow pages and interior B-tree pages.
 */
function buildDb(setup) {
    const dir  = fs.mkdtempSync(path.join(os.tmpdir(), 'syno-inspector-'));
    const file = path.join(dir, 'fixture.db');
    try {
        const db = new DatabaseSync(file);
        db.exec('PRAGMA page_size = 1024; VACUUM;');
        db.exec('BEGIN');
        setup(db);
        db.exec('COMMIT');
        db.close();
        return new Uint8Array(fs.readFileSync(file));
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

test('reads negative integers of every serial type width', () => {
    const app = loadApp();
    const values = [-1, -128, -129, -32768, -8388608, -2147483648, -140737488355328, 1, 255, 32767, 2147483647];
    const bytes = buildDb(db => {
        db.exec('CREATE TABLE t (v INTEGER)');
        const ins = db.prepare('INSERT INTO t VALUES (?)');
        for (const v of values) ins.run(v);
    });
    const rows = app.readSQLiteTable(bytes, 't').map(r => Number(r[0]));
    assert.deepEqual(plain(rows), values);
});

test('reads floating point values', () => {
    const app = loadApp();
    const bytes = buildDb(db => {
        db.exec('CREATE TABLE t (v REAL)');
        db.prepare('INSERT INTO t VALUES (?)').run(-12.5);
    });
    assert.equal(app.readSQLiteTable(bytes, 't')[0][0], -12.5);
});

test('reads values spread over overflow pages without picking up foreign bytes', () => {
    const app = loadApp();
    const big = 'A'.repeat(5000) + 'END';
    const bytes = buildDb(db => {
        db.exec('CREATE TABLE confbkp_config_tb (config_key TEXT, config_value TEXT)');
        const ins = db.prepare('INSERT INTO confbkp_config_tb VALUES (?, ?)');
        ins.run('BIG_value', big);
        for (let i = 0; i < 400; i++) ins.run(`KEY_${i}`, `value-${i}`);
    });
    const map = app.buildSynoConfigMap(bytes);
    assert.equal(map.get('BIG_value'), big);
    assert.equal(map.size, 401);
    assert.equal(map.get('KEY_399'), 'value-399');
});

test('extracts users, administrators and share permissions', () => {
    const app = loadApp();
    const bytes = buildDb(db => {
        db.exec(`CREATE TABLE confbkp_user_tb (name TEXT, uid INTEGER, gid INTEGER, description TEXT,
                 mail TEXT, passwd TEXT, LMPW TEXT, NTPW TEXT, disallowChPasswd INTEGER, expire INTEGER,
                 authType INTEGER, pwd_no_expiry INTEGER)`);
        const u = db.prepare('INSERT INTO confbkp_user_tb (name, uid, expire) VALUES (?, ?, ?)');
        u.run('admin', 1024, -1);
        u.run('guest', 1025, 1);
        u.run('alice', 1026, 19000);
        db.exec('CREATE TABLE confbkp_group_member_list_tb (group_name TEXT, member_name TEXT)');
        db.exec("INSERT INTO confbkp_group_member_list_tb VALUES ('administrators', 'admin'), ('users', 'alice')");
        db.exec('CREATE TABLE confbkp_share_privilege_id_tb (share_name TEXT, user_or_group TEXT, id INTEGER, name TEXT, privilege TEXT)');
        db.exec("INSERT INTO confbkp_share_privilege_id_tb VALUES ('public', 'user', 1025, 'guest', 'RO')");
    });
    const ex = app.buildSynoExtras(bytes);
    assert.deepEqual(plain(ex.users.map(u => [u.name, u.uid, u.expire])),
        [['admin', 1024, -1], ['guest', 1025, 1], ['alice', 1026, 19000]]);
    assert.deepEqual(plain(ex.adminMembers), ['admin']);
    assert.deepEqual(plain(ex.sharePrivileges),
        [{ share: 'public', type: 'user', name: 'guest', privilege: 'RO' }]);
    assert.equal(ex.autoBackupConfigured, null);
});
