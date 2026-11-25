/**
 * compare-view.js
 *
 * Renders the comparison of the system settings of two backups.
 *
 * Depends on: compare.js (diffConfigMaps), i18n.js,
 *             app.js (escapeHtml, describeBackup, rerenderKeepingFocus, announce)
 */

const compareState = {
    showAll: false,   // false: only rows that are not "same"
};

const COMPARE_STATUS_TEXT = {
    changed: 'compareStatusChanged',
    same:    'compareStatusSame',
    onlyA:   'compareStatusOnlyA',
    onlyB:   'compareStatusOnlyB',
    unknown: 'compareStatusUnknown',
};

function toggleCompareShowAll() {
    compareState.showAll = !compareState.showAll;
    rerenderKeepingFocus(renderApp);
    const shown = document.querySelectorAll('.compare-row').length;
    announce(t('announceFiltered', shown));
}

function compareCounts(entries) {
    const counts = { changed: 0, same: 0, onlyA: 0, onlyB: 0, unknown: 0 };
    for (const entry of entries) counts[entry.status]++;
    return counts;
}

function compareSummaryText(counts) {
    return t('compareSummary', counts.changed, counts.onlyA, counts.onlyB, counts.unknown);
}

/** Text for one side of a row; the diff only carries values that are safe to show. */
function renderCompareValue(config, key, shownValue) {
    if (!config.has(key))        return `<span class="compare-value--note">${t('compareValueMissing')}</span>`;
    if (config.get(key) === null) return `<span class="compare-value--note">${t('compareValueUnreadable')}</span>`;
    if (shownValue === null)     return `<span class="compare-value--note">${t('compareValueHidden')}</span>`;
    if (shownValue === '')       return `<span class="compare-value--note">${t('compareValueEmpty')}</span>`;
    return `<code>${escapeHtml(shownValue)}</code>`;
}

function renderCompareSide(label, parseResult) {
    const { version, model, hostname } = describeBackup(parseResult);
    return `
        <div class="compare-side">
            <h3 class="compare-side-title">${label}</h3>
            <dl class="compare-side-list">
                <dt>${t('labelFileName')}</dt><dd>${escapeHtml(parseResult.fileName)}</dd>
                <dt>${t('labelModel')}</dt><dd>${escapeHtml(model)}</dd>
                <dt>${t('labelDSMVersion')}</dt><dd>${escapeHtml(version)}</dd>
                <dt>${t('labelHostname')}</dt><dd>${escapeHtml(hostname)}</dd>
            </dl>
        </div>
    `;
}

function renderCompareRows(entries, configA, configB) {
    const groups = new Map();
    for (const entry of entries) {
        const group = entry.key.split('_')[0];
        if (!groups.has(group)) groups.set(group, []);
        groups.get(group).push(entry);
    }
    return [...groups].map(([group, rows]) => `
        <tbody>
            <tr><th scope="rowgroup" colspan="4" class="compare-group">${escapeHtml(group)}</th></tr>
            ${rows.map(entry => `
            <tr class="compare-row compare-row--${entry.status}">
                <th scope="row"><code>${escapeHtml(entry.key)}</code></th>
                <td>${renderCompareValue(configA, entry.key, entry.a)}</td>
                <td>${renderCompareValue(configB, entry.key, entry.b)}</td>
                <td class="compare-status">${t(COMPARE_STATUS_TEXT[entry.status])}</td>
            </tr>`).join('')}
        </tbody>
    `).join('');
}

/**
 * @param {Object} resultA  parse result of the first backup
 * @param {Object} resultB  parse result of the second backup
 * @returns {string} HTML
 */
function renderCompareView(resultA, resultB) {
    const entries = diffConfigMaps(resultA.config, resultB.config);
    const counts  = compareCounts(entries);
    const visible = compareState.showAll ? entries : entries.filter(e => e.status !== 'same');

    const table = visible.length
        ? `
            <div class="compare-scroll" tabindex="0" role="region" aria-label="${t('compareTableLabel')}">
                <table class="compare-table">
                    <thead>
                        <tr>
                            <th scope="col">${t('compareColSetting')}</th>
                            <th scope="col">${t('compareSideA')}</th>
                            <th scope="col">${t('compareSideB')}</th>
                            <th scope="col">${t('compareColResult')}</th>
                        </tr>
                    </thead>
                    ${renderCompareRows(visible, resultA.config, resultB.config)}
                </table>
            </div>`
        : `<p class="compare-empty">${t('compareNoDifferences')}</p>`;

    return `
        <div class="compare-header">
            <div class="compare-header-top">
                <h2 class="bp-title" id="view-heading" tabindex="-1">${t('compareTitle')}</h2>
                <button type="button" class="fd-button fd-button--ghost" onclick="resetApp()">
                    ${t('compareBtnNew')}
                </button>
            </div>
            <div class="compare-sides">
                ${renderCompareSide(t('compareSideA'), resultA)}
                ${renderCompareSide(t('compareSideB'), resultB)}
            </div>
            <p class="compare-summary">${compareSummaryText(counts)}</p>
            <p class="compare-note">${t('compareScope')} ${t('compareHiddenNote')}</p>
            <button type="button" class="compare-toggle" data-focus-key="compare-show-all"
                    aria-pressed="${compareState.showAll}" onclick="toggleCompareShowAll()">
                ${t('compareShowAll')}
            </button>
        </div>
        ${table}
    `;
}
