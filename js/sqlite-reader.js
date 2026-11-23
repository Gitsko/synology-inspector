/**
 * sqlite-reader.js
 *
 * Minimal SQLite 3 database reader.
 * Performs a full table scan of a single named table and returns all rows
 * as arrays of column values.
 *
 * Supported page types: leaf table (0x0D), interior table (0x05).
 * Overflow pages are followed, so values larger than the inline threshold
 * (e.g. NOTIFY_filter, DDNS_provider) are read completely.
 *
 * SQLite 3 format reference: https://www.sqlite.org/fileformat.html
 */

// ── Low-level helpers ─────────────────────────────────────────────────────────

function sqliteReadU16(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function sqliteReadU32(bytes, offset) {
    return (((bytes[offset] << 24) | (bytes[offset + 1] << 16) |
              (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0);
}

/**
 * Read a SQLite varint (big-endian, 1–9 bytes, 7 bits per byte).
 * Returns { value, length }.
 */
function sqliteReadVarint(bytes, offset) {
    let value = 0;
    let length = 0;
    for (let i = 0; i < 9; i++) {
        const b = bytes[offset + i];
        length++;
        if (i < 8) {
            value = value * 128 + (b & 0x7f);
            if (!(b & 0x80)) break;
        } else {
            value = value * 256 + b; // 9th byte: all 8 bits
        }
    }
    return { value, length };
}

/** Byte length of the integer serial types 1–6. */
const SQLITE_INT_SIZES = [0, 1, 2, 3, 4, 6, 8];

/**
 * Read a big-endian two's complement integer of `len` bytes.
 * 8-byte values outside the safe integer range lose precision.
 */
function sqliteReadSignedInt(bytes, offset, len) {
    let v = 0n;
    for (let i = 0; i < len; i++) v = (v << 8n) | BigInt(bytes[offset + i]);
    const bits = BigInt(len * 8);
    if (v & (1n << (bits - 1n))) v -= 1n << bits;
    return Number(v);
}

/**
 * Assemble the full payload of a table b-tree cell, following overflow pages.
 * See "Cell Payload Overflow Pages" in the SQLite file format reference.
 *
 * @param {Uint8Array} bytes        Full database bytes
 * @param {number}     offset       Offset of the first payload byte
 * @param {number}     payloadLen   Total payload length (P)
 * @param {number}     pageSize
 * @param {number}     usableSize   Page size minus reserved bytes (U)
 * @returns {Uint8Array}
 */
function sqliteReadCellPayload(bytes, offset, payloadLen, pageSize, usableSize) {
    if (payloadLen > bytes.length) throw new RangeError('payload length exceeds database size');
    const maxLocal = usableSize - 35;
    if (payloadLen <= maxLocal) {
        return bytes.slice(offset, offset + payloadLen);
    }

    const minLocal = Math.floor((usableSize - 12) * 32 / 255) - 23;
    const k        = minLocal + ((payloadLen - minLocal) % (usableSize - 4));
    const localLen = k <= maxLocal ? k : minLocal;

    const payload = new Uint8Array(payloadLen);
    payload.set(bytes.subarray(offset, offset + localLen), 0);

    let written  = localLen;
    let nextPage = sqliteReadU32(bytes, offset + localLen);
    const visited = new Set();
    while (written < payloadLen && nextPage !== 0 && !visited.has(nextPage)) {
        visited.add(nextPage);
        const pageOffset = (nextPage - 1) * pageSize;
        if (pageOffset + 4 > bytes.length) break;
        const wanted   = Math.min(usableSize - 4, payloadLen - written);
        const chunk    = bytes.subarray(pageOffset + 4, pageOffset + 4 + wanted);
        payload.set(chunk, written);
        written  += chunk.length;
        if (chunk.length < wanted) break;   // truncated file
        nextPage  = sqliteReadU32(bytes, pageOffset);
    }

    return written === payloadLen ? payload : payload.slice(0, written);
}

// ── Record decoder ────────────────────────────────────────────────────────────

/**
 * Decode a SQLite record payload into an array of column values.
 * Text columns → string, integer columns → number, NULL → null, blob → Uint8Array.
 */
function sqliteDecodeRecord(payload) {
    const decoder = new TextDecoder('utf-8', { fatal: false });
    let pos = 0;

    // Header: total header length varint, then one varint per column (serial type)
    const hdrSizeV = sqliteReadVarint(payload, pos);
    const headerSize = hdrSizeV.value;
    pos += hdrSizeV.length;
    if (headerSize < pos || headerSize > payload.length) {
        throw new Error('Malformed record header');
    }

    const serialTypes = [];
    while (pos < headerSize) {
        const stV = sqliteReadVarint(payload, pos);
        serialTypes.push(stV.value);
        pos += stV.length;
    }

    pos = headerSize; // data section starts here
    const values = [];

    for (const st of serialTypes) {
        if (pos > payload.length) { values.push(null); continue; }

        if (st === 0) {
            values.push(null);
        } else if (st >= 1 && st <= 6) {
            // Big-endian two's complement integers of 1, 2, 3, 4, 6 or 8 bytes
            const len = SQLITE_INT_SIZES[st];
            if (pos + len > payload.length) { values.push(null); pos = payload.length; continue; }
            values.push(sqliteReadSignedInt(payload, pos, len)); pos += len;
        } else if (st === 7) {
            if (pos + 8 > payload.length) { values.push(null); pos = payload.length; continue; }
            const view = new DataView(payload.buffer, payload.byteOffset + pos, 8);
            values.push(view.getFloat64(0, false)); pos += 8;
        } else if (st === 8) {
            values.push(0);
        } else if (st === 9) {
            values.push(1);
        } else if (st >= 12 && st % 2 === 0) {
            const len = (st - 12) / 2;
            if (pos + len > payload.length) { values.push(null); pos = payload.length; continue; }
            values.push(payload.slice(pos, pos + len)); pos += len;
        } else if (st >= 13 && st % 2 === 1) {
            const len = (st - 13) / 2;
            const available = Math.min(len, payload.length - pos);
            values.push(decoder.decode(payload.slice(pos, pos + available)));
            pos += available;
        } else {
            values.push(null);
        }
    }

    return values;
}

// ── B-tree traversal ──────────────────────────────────────────────────────────

// SQLite itself refuses trees deeper than 20 levels (BTCURSOR_MAX_DEPTH)
const SQLITE_MAX_TREE_DEPTH = 20;

/**
 * Recursively scan all leaf pages of a table B-tree.
 * Returns an array of decoded rows (each row is an array of column values).
 *
 * @param {Uint8Array} bytes      Full database bytes
 * @param {number}     pageNum    1-based page number to scan
 * @param {number}     pageSize   Database page size in bytes
 * @param {number}     usableSize Page size minus reserved bytes per page
 * @param {Set<number>} [visited] Pages already scanned; a corrupt file may link
 *                                a page more than once or into a cycle
 * @param {number}     [depth]    Current tree depth
 * @returns {Array[]}
 */
function sqliteScanBTree(bytes, pageNum, pageSize, usableSize, visited = new Set(), depth = 0) {
    const results = [];
    const pageCount = Math.floor(bytes.length / pageSize);
    if (!Number.isInteger(pageNum) || pageNum < 1 || pageNum > pageCount) return results;
    if (visited.has(pageNum) || depth > SQLITE_MAX_TREE_DEPTH) return results;
    visited.add(pageNum);
    const pageOffset = (pageNum - 1) * pageSize;
    const isPage1   = (pageNum === 1);
    const hdrOffset = isPage1 ? pageOffset + 100 : pageOffset; // page 1 has 100-byte DB header

    const pageType = bytes[hdrOffset];
    const numCells = sqliteReadU16(bytes, hdrOffset + 3);

    if (pageType === 0x0D) {
        // ── Leaf table page ────────────────────────────────────────────────
        // 8-byte page header; cell pointer array starts immediately after
        const cellPtrBase = hdrOffset + 8;

        for (let i = 0; i < numCells; i++) {
            const cellPtr    = sqliteReadU16(bytes, cellPtrBase + i * 2);
            let   cellOffset = pageOffset + cellPtr;

            // Varint: total payload length
            const payloadLenV = sqliteReadVarint(bytes, cellOffset);
            cellOffset += payloadLenV.length;

            // Varint: integer row key
            const rowIdV = sqliteReadVarint(bytes, cellOffset);
            cellOffset += rowIdV.length;

            try {
                const payload = sqliteReadCellPayload(
                    bytes, cellOffset, payloadLenV.value, pageSize, usableSize);
                results.push(sqliteDecodeRecord(payload));
            } catch (_) {
                // Skip malformed records rather than aborting the scan
            }
        }
    } else if (pageType === 0x05) {
        // ── Interior table page ────────────────────────────────────────────
        // 12-byte page header (8 + 4-byte rightmost child page number)
        const rightChildPage = sqliteReadU32(bytes, hdrOffset + 8);
        const cellPtrBase    = hdrOffset + 12;

        for (let i = 0; i < numCells; i++) {
            const cellPtr   = sqliteReadU16(bytes, cellPtrBase + i * 2);
            const cellOffset = pageOffset + cellPtr;
            // Cell: 4-byte left child page number + varint key (key not needed)
            const childPage = sqliteReadU32(bytes, cellOffset);
            for (const row of sqliteScanBTree(bytes, childPage, pageSize, usableSize, visited, depth + 1)) results.push(row);
        }

        // Process the rightmost child (loop instead of spread: large subtrees
        // would exceed the engine's argument limit)
        for (const row of sqliteScanBTree(bytes, rightChildPage, pageSize, usableSize, visited, depth + 1)) results.push(row);
    }

    return results;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Read all rows from a named table in a SQLite 3 database.
 *
 * @param {ArrayBuffer|Uint8Array} buffer  Raw SQLite 3 database bytes
 * @param {string}                 tableName
 * @returns {Array[]}  Array of rows; each row is an array of column values
 * @throws  {Error}    If the buffer is not a valid SQLite 3 database
 */
function readSQLiteTable(buffer, tableName) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

    // Validate SQLite 3 magic string (first 16 bytes)
    const magic = new TextDecoder('ascii', { fatal: false }).decode(bytes.slice(0, 15));
    if (magic !== 'SQLite format 3') {
        throw new Error('Not a SQLite 3 database');
    }

    // Page size (bytes 16–17, big-endian); value 1 means 65536
    let pageSize = sqliteReadU16(bytes, 16);
    if (pageSize === 1) pageSize = 65536;

    // Reserved space at the end of each page (byte 20)
    const usableSize = pageSize - bytes[20];

    // sqlite_master is always at page 1.
    // Schema: type TEXT, name TEXT, tbl_name TEXT, rootpage INTEGER, sql TEXT
    const masterRows = sqliteScanBTree(bytes, 1, pageSize, usableSize);

    let rootPage = null;
    for (const row of masterRows) {
        if (row[0] === 'table' && row[1] === tableName) {
            rootPage = Number(row[3]);
            break;
        }
    }

    if (!rootPage) return [];

    return sqliteScanBTree(bytes, rootPage, pageSize, usableSize);
}

/**
 * Build a Map from a confbkp_config_tb-style table (key TEXT, value TEXT).
 *
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {Map<string, string>}
 */
function buildSynoConfigMap(buffer) {
    const rows = readSQLiteTable(buffer, 'confbkp_config_tb');
    const map  = new Map();
    for (const row of rows) {
        if (typeof row[0] === 'string' && row[0].length > 0) {
            map.set(row[0], typeof row[1] === 'string' ? row[1] : null);
        }
    }
    return map;
}

/**
 * Build supplementary data needed by security and best-practice checks.
 *
 * Column indices are fixed by the Synology DSM .dss schema:
 *   confbkp_user_tb:             name(0), uid(1), expire(9)
 *   confbkp_group_member_list_tb: group_name(0), member_name(1)
 *   confbkp_share_privilege_id_tb: share_name(0), user_or_group(1), name(3), privilege(4)
 *   confbkp_scheduler_table:     id(0), json_config(1)
 *   confbkp_auto_config_backup_table: key(0), value(1)
 *   confbkp_smartblock_table:    key(0), value(1)
 *   confbkp_volume_tb:           vid(0), location(1), fstype(2), mount_point(3)
 *
 * Scheduler json_config is double-encoded: outer JSON object, inner values
 * are themselves JSON strings (e.g. '"SYNO.SDS.TaskScheduler.Recycle"\n').
 *
 * @param {ArrayBuffer|Uint8Array} buffer  Raw SQLite 3 database bytes
 * @returns {{ users, adminMembers, sharePrivileges, schedulerTasks, autoBackupConfigured: boolean|null,
 *             accountProtectionEnabled: boolean|null, hasBtrfs }}
 */
function buildSynoExtras(buffer) {
    // ── Users ────────────────────────────────────────────────────────────────────
    // expire: -1 = never expires, 1 = deactivated, >1 = expiry day (see isAccountActive)
    const userRows = readSQLiteTable(buffer, 'confbkp_user_tb');
    const users = userRows
        .filter(r => typeof r[0] === 'string' && r[0].length > 0)
        .map(r => ({ name: r[0], uid: Number(r[1]) || 0, expire: Number(r[9]) }));

    // ── Administrators group members ─────────────────────────────────────────────
    const groupRows   = readSQLiteTable(buffer, 'confbkp_group_member_list_tb');
    const adminMembers = groupRows
        .filter(r => r[0] === 'administrators' && typeof r[1] === 'string' && r[1].length > 0)
        .map(r => r[1]);

    // ── Explicit share permissions ───────────────────────────────────────────────
    // privilege: 'RW', 'RO' or 'Deny'; user_or_group: 'user' or 'group'
    const sharePrivileges = readSQLiteTable(buffer, 'confbkp_share_privilege_id_tb')
        .filter(r => typeof r[0] === 'string' && typeof r[3] === 'string')
        .map(r => ({ share: r[0], type: r[1], name: r[3], privilege: r[4] }));

    // ── Scheduler tasks ──────────────────────────────────────────────────────────
    const schedRows      = readSQLiteTable(buffer, 'confbkp_scheduler_table');
    const schedulerTasks = [];
    const decodeInner = v => {
        if (typeof v !== 'string') return '';
        try { return JSON.parse(v.trim()); } catch (_) { return v.trim(); }
    };
    for (const row of schedRows) {
        if (typeof row[1] !== 'string') continue;
        try {
            const outer = JSON.parse(row[1]);
            schedulerTasks.push({
                app:   decodeInner(outer['app']),
                state: decodeInner(outer['state']),
                name:  decodeInner(outer['name']),
            });
        } catch (_) {}
    }

    // ── Auto config backup ───────────────────────────────────────────────────────
    // not_set_before = 'true' means backup has NOT been configured yet.
    // null = table or key missing, the state cannot be determined.
    const backupRows = readSQLiteTable(buffer, 'confbkp_auto_config_backup_table');
    const backupMap  = new Map(backupRows.map(r => [r[0], r[1]]));
    const notSetBefore = backupMap.get('not_set_before');
    const autoBackupConfigured = notSetBefore === 'false' ? true : notSetBefore === 'true' ? false : null;

    // ── Account protection ───────────────────────────────────────────────────────
    // SmartBlock_0 is the on/off switch, stored with a leading space (' 1').
    // SmartBlock_1..6 hold the attempt and time limits for untrusted and
    // trusted clients (confirmed against the DSM UI on a DSM 7.4 backup).
    const smartBlockRows = readSQLiteTable(buffer, 'confbkp_smartblock_table');
    const smartBlockOn = smartBlockRows.find(r => r[0] === 'SmartBlock_0')?.[1];
    const smartBlockFlag = typeof smartBlockOn === 'string' ? smartBlockOn.trim() : null;
    const accountProtectionEnabled = smartBlockFlag === '1' ? true : smartBlockFlag === '0' ? false : null;

    // ── btrfs volumes ────────────────────────────────────────────────────────────
    // fstype = 3 → btrfs
    const volRows  = readSQLiteTable(buffer, 'confbkp_volume_tb');
    const hasBtrfs = volRows.some(r => Number(r[2]) === 3);

    return { users, adminMembers, sharePrivileges, schedulerTasks, autoBackupConfigured,
        accountProtectionEnabled, hasBtrfs };
}
