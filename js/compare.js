/**
 * compare.js
 *
 * Compares the system settings (confbkp_config_tb) of two backups.
 * Every value is compared, but a value is only returned for display when it
 * is short and its key does not look like it holds a secret or personal data.
 * Anything else is reported as "differs" without the value (fail closed).
 */

const COMPARE_MAX_SHOWN_LENGTH = 32;
const COMPARE_SECRET_KEY = /passw|pwd|secret|token|key|conf|priv|cert|mail|pair/i;

function compareDisplayValue(key, value) {
    if (typeof value !== 'string') return null;
    if (value.length > COMPARE_MAX_SHOWN_LENGTH) return null;
    if (COMPARE_SECRET_KEY.test(key)) return null;
    return value;
}

/**
 * @param {Map<string, string|null>} configA
 * @param {Map<string, string|null>} configB
 * @returns {{key: string, status: string, a: string|null, b: string|null}[]}
 *   status: onlyA, onlyB, same, changed, or unknown (a value could not be read)
 */
function diffConfigMaps(configA, configB) {
    const keys = [...new Set([...configA.keys(), ...configB.keys()])].sort();
    return keys.map(key => {
        const inA = configA.has(key);
        const inB = configB.has(key);
        const valueA = configA.get(key);
        const valueB = configB.get(key);

        let status;
        if (!inB)                                      status = 'onlyA';
        else if (!inA)                                 status = 'onlyB';
        else if (valueA === null || valueB === null)   status = 'unknown';
        else if (valueA === valueB)                    status = 'same';
        else                                           status = 'changed';

        return {
            key,
            status,
            a: compareDisplayValue(key, valueA),
            b: compareDisplayValue(key, valueB),
        };
    });
}
