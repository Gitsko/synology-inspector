'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('node:fs');
const path   = require('node:path');
const vm     = require('node:vm');
const { ROOT } = require('./load-app.js');

function load(window = {}) {
    const context = { window, TextDecoder, ReadableStream, t: k => k };
    vm.createContext(context);
    for (const file of ['js/tar-parser.js', 'js/dss-pipeline.js']) {
        vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), context, { filename: file });
    }
    return context;
}

/** Build a ustar archive; `truncate` cuts bytes off the end. */
function tar(files, truncate = 0) {
    const blocks = [];
    for (const [name, content] of files) {
        const data = Buffer.from(content);
        const hdr = Buffer.alloc(512);
        hdr.write(name, 0);
        hdr.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
        hdr.write('0', 156);
        hdr.write('ustar\0', 257);
        blocks.push(hdr, data, Buffer.alloc((512 - data.length % 512) % 512));
    }
    const all = Buffer.concat([...blocks, Buffer.alloc(1024)]);
    return new Uint8Array(truncate ? all.subarray(0, all.length - 1024 - truncate) : all);
}

test('a member whose data runs past the end of the archive is dropped', () => {
    const app = load();
    const entries = app.parseTar(tar([['ConfigBkp/config_info', 'a'], ['ConfigBkp/_Syno_ConfBkp.db', 'x'.repeat(1000)]], 100));
    assert.deepEqual([...entries.map(e => e.name)], ['ConfigBkp/config_info']);
});

test('backup members are found by their full path component, not a suffix', () => {
    const app = load();
    const entries = [
        { name: 'ConfigBkp/evil_Syno_ConfBkp.db' },
        { name: 'ConfigBkp/old_config_info' },
        { name: 'ConfigBkp/_Syno_ConfBkp.db' },
        { name: './ConfigBkp/config_info' },
    ];
    assert.equal(app.findTarEntry(entries, '_Syno_ConfBkp.db').name, 'ConfigBkp/_Syno_ConfBkp.db');
    assert.equal(app.findTarEntry(entries, 'config_info').name, './ConfigBkp/config_info');
    assert.equal(app.findTarEntry([{ name: '_Syno_ConfBkp.db' }], '_Syno_ConfBkp.db').name, '_Syno_ConfBkp.db');
    assert.equal(app.findTarEntry(entries, 'tls_profile/datastore.json'), undefined);
});

test('decompression stops once the output exceeds the size limit', async () => {
    let cancelled = false;
    let reads = 0;
    class EndlessXz {
        constructor() {}
        getReader() {
            return {
                // 100 KiB in total: well above the 10 KiB limit used below
                read: async () => (++reads > 100 ? { done: true } : { done: false, value: new Uint8Array(1024) }),
                cancel: async () => { cancelled = true; },
            };
        }
    }
    const app = load({ 'xz-decompress': { XzReadableStream: EndlessXz } });
    await assert.rejects(app.decompressXZ(new Uint8Array(1), 10 * 1024), /too large/i);
    assert.ok(cancelled, 'the stream must be cancelled');
});
