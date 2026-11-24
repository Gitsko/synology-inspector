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
    const values = [-1, -128, -129, -32768, -8388608, -2147483648, -140737488355328, -9007199254740991, 1, 255, 32767, 2147483647];
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

test('a truncated overflow chain yields a shorter value, not padded bytes', () => {
    const app = loadApp();
    const bytes = buildDb(db => {
        db.exec('CREATE TABLE confbkp_config_tb (config_key TEXT, config_value TEXT)');
        db.prepare('INSERT INTO confbkp_config_tb VALUES (?, ?)').run('BIG', 'A'.repeat(1499) + 'Z');
    });
    const value = app.buildSynoConfigMap(bytes.subarray(0, bytes.length - 1)).get('BIG');
    assert.ok(value === null || !value.includes('\u0000'), 'no NUL padding');
});

test('auto config backup state needs an explicit true/false flag', () => {
    const app = loadApp();
    const state = flag => app.buildSynoExtras(buildDb(db => {
        db.exec('CREATE TABLE confbkp_auto_config_backup_table (key TEXT, value TEXT)');
        db.prepare('INSERT INTO confbkp_auto_config_backup_table VALUES (?, ?)').run('not_set_before', flag);
    })).autoBackupConfigured;
    assert.equal(state('false'), true);
    assert.equal(state('true'), false);
    assert.equal(state(null), null);
});

test('account protection state comes from SmartBlock_0, padded as in real backups', () => {
    const app = loadApp();
    // Untyped value column so an integer flag stays an integer
    const state = flag => app.buildSynoExtras(buildDb(db => {
        db.exec('CREATE TABLE confbkp_smartblock_table (key TEXT, value)');
        const ins = db.prepare('INSERT INTO confbkp_smartblock_table VALUES (?, ?)');
        ins.run('SmartBlock_1', ' 0');
        ins.run('SmartBlock_0', flag);
        ins.run('SmartBlock_2', ' 1');
    })).accountProtectionEnabled;
    assert.equal(state(' 1'), true);
    assert.equal(state(' 0'), false);
    assert.equal(state(1n), true);
    assert.equal(state(0n), false);
    assert.equal(state('yes'), null);
    assert.equal(state(null), null);
    assert.equal(app.buildSynoExtras(buildDb(() => {})).accountProtectionEnabled, null);
});

test('a record whose header promises more bytes than the payload holds yields null values', () => {
    const app = loadApp();
    // header: size 4, serial types 1 (1-byte int), 6 (8-byte int), 7 (float); body has only 2 bytes
    const payload = new Uint8Array([4, 1, 6, 7, 0x2a, 0x01]);
    assert.deepEqual(plain(app.sqliteDecodeRecord(payload)), [42, null, null]);
});

test('a cell with an impossible payload length is skipped, not fatal', () => {
    const app = loadApp();
    const bytes = buildDb(db => {
        db.exec('CREATE TABLE confbkp_config_tb (config_key TEXT, config_value TEXT)');
        const ins = db.prepare('INSERT INTO confbkp_config_tb VALUES (?, ?)');
        ins.run('A', 'first');
        ins.run('B', 'second');
    });
    // Corrupt the payload length varint of the first cell on the table's leaf page
    const pageSize = (bytes[16] << 8) | bytes[17];
    const leaf = pageSize;                                   // page 2
    const cellPtr = (bytes[leaf + 8] << 8) | bytes[leaf + 9];
    bytes.fill(0xff, leaf + cellPtr, leaf + cellPtr + 9);   // 9-byte varint: far beyond any allocatable size
    let map;
    assert.doesNotThrow(() => { map = app.buildSynoConfigMap(bytes); });
    assert.ok(map.size <= 2);
});

test('a record header size beyond the payload is rejected without reading past it', () => {
    const app = loadApp();
    // header size varint 0x0fffffff, followed by a few bytes only
    const payload = new Uint8Array([0xff, 0xff, 0xff, 0x7f, 1, 1, 1, 1, 1, 1]);
    assert.throws(() => app.sqliteDecodeRecord(payload), /header/i);
});

test('a record header size smaller than its own varint is rejected', () => {
    const app = loadApp();
    assert.throws(() => app.sqliteDecodeRecord(new Uint8Array([0, 1])), /header/i);
});

function tableBytes(rows) {
    return buildDb(db => {
        db.exec('CREATE TABLE confbkp_config_tb (config_key TEXT, config_value TEXT)');
        const ins = db.prepare('INSERT INTO confbkp_config_tb VALUES (?, ?)');
        for (let i = 0; i < rows; i++) ins.run(`KEY_${i}`, `value-${i}`);
    });
}

test('a truncated last page still counts as part of the file', () => {
    const app = loadApp();
    const bytes = tableBytes(400);
    const rows = app.readSQLiteTable(bytes.subarray(0, bytes.length - 1), 'confbkp_config_tb');
    assert.equal(rows.length, 400);
});

test('an interior page that points at itself is rejected as corrupt', () => {
    const app = loadApp();
    const bytes = tableBytes(2);
    const pageSize = (bytes[16] << 8) | bytes[17];
    const root = pageSize;                                   // page 2, a leaf
    bytes[root] = 0x05;                                      // turn it into an interior page
    bytes[root + 3] = 0; bytes[root + 4] = 0;                // no cells
    bytes.set([0, 0, 0, 2], root + 8);                       // rightmost child = itself
    assert.throws(() => app.readSQLiteTable(bytes, 'confbkp_config_tb'), /linked more than once/);
});

test('a child page referenced twice is rejected as corrupt', () => {
    const app = loadApp();
    const bytes = tableBytes(400);
    const pageSize = (bytes[16] << 8) | bytes[17];
    const root = pageSize;
    assert.equal(bytes[root], 0x05, 'fixture must have an interior root page');
    const cellPtr = (bytes[root + 12] << 8) | bytes[root + 13];
    bytes.copyWithin(root + 8, root + cellPtr, root + cellPtr + 4);   // rightmost child = first child
    assert.throws(() => app.readSQLiteTable(bytes, 'confbkp_config_tb'), /linked more than once/);
});

test('child page numbers outside the file are rejected as corrupt', () => {
    const app = loadApp();
    const bytes = tableBytes(400);
    const root = (bytes[16] << 8) | bytes[17];
    bytes.set([0x7f, 0xff, 0xff, 0xff], root + 8);
    assert.throws(() => app.readSQLiteTable(bytes, 'confbkp_config_tb'), /outside the database/);
});

test('a B-tree deeper than SQLite allows is rejected as corrupt', () => {
    const app = loadApp();
    // Chain of interior pages 1 -> 2 -> ... -> 30, each with no cells and a rightmost child
    const pageSize = 512, pages = 30;
    const bytes = new Uint8Array(pageSize * pages);
    for (let n = 1; n <= pages; n++) {
        const base = (n - 1) * pageSize;
        bytes[base] = 0x05;
        new DataView(bytes.buffer).setUint32(base + 8, n + 1 > pages ? n : n + 1);
    }
    assert.throws(() => app.sqliteScanBTree(bytes, 2, pageSize, pageSize), /deeper/);
});
