'use strict';

/**
 * Dynamic CSV-driven data + filters for the ZKP Tools Explorer
 * - Loads ./data.csv via fetch()
 * - Parses CSV (supports quoted fields with commas/newlines)
 * - Builds enum filter options from data
 * - Uses existing global search input for free-text (string) fields
 *
 * No external libraries required.
 */

/* ----------------------------- CSV parsing ----------------------------- */

function parseCSV(csvText) {
  // RFC4180-ish parser: commas, quotes, CRLF/LF, quoted newlines, escaped quotes ("")
  const rows = [];
  let row = [];
  let cur = '';
  let inQuotes = false;

  for (let i = 0; i < csvText.length; i++) {
    const c = csvText[i];

    if (inQuotes) {
      if (c === '"') {
        const next = csvText[i + 1];
        if (next === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += c;
      }
      continue;
    }

    if (c === '"') {
      inQuotes = true;
      continue;
    }

    if (c === ',') {
      row.push(cur);
      cur = '';
      continue;
    }

    if (c === '\r') {
      // ignore
      continue;
    }

    if (c === '\n') {
      row.push(cur);
      cur = '';
      // Avoid pushing a trailing empty line
      const isAllEmpty = row.every(cell => String(cell || '').trim() === '');
      if (!isAllEmpty) rows.push(row);
      row = [];
      continue;
    }

    cur += c;
  }

  // Last cell / row
  row.push(cur);
  const isAllEmpty = row.every(cell => String(cell || '').trim() === '');
  if (!isAllEmpty) rows.push(row);

  return rows;
}

function normalizeEmpty(v) {
  if (v == null) return '';
  const t = String(v).trim();
  if (!t) return '';
  if (/^nan$/i.test(t)) return '';
  if (t === '🤷') return '';
  return t;
}

function splitList(v) {
  // For columns that are "list of ..." (links, enums, developers)
  // Supports comma-separated and/or newline-separated.
  const t = normalizeEmpty(v);
  if (!t) return [];
  return t
    .split(/[\n]+|,(?![^()]*\))/g) // split on newlines or commas (basic tolerance)
    .map(s => s.trim())
    .filter(Boolean);
}

function monthYearToDate(v) {
  // Accepts formats like: "Mar 2024", "Jun 2025", "2024-03", "2024-03-01", "Mar 2024 "
  const t = normalizeEmpty(v);
  if (!t) return null;

  // ISO-ish
  const iso = Date.parse(t);
  if (!Number.isNaN(iso)) return new Date(iso);

  const m = t.match(/^([A-Za-z]{3,})\s+(\d{4})$/);
  if (!m) return null;

  const monthStr = m[1].slice(0, 3).toLowerCase();
  const year = parseInt(m[2], 10);

  const monthMap = {
    jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
    jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11
  };
  if (!(monthStr in monthMap)) return null;

  return new Date(Date.UTC(year, monthMap[monthStr], 1));
}

function normalizeMaintained(v) {
  const t = normalizeEmpty(v).toLowerCase();
  if (!t) return '';
  if (t === 'yes' || t === 'y' || t === 'true') return 'Yes';
  if (t === 'no' || t === 'n' || t === 'false') return 'No';
  if (t === 'stale') return 'Stale';
  return normalizeEmpty(v); // keep as-is if unexpected
}

function normalizeZkpClass(v) {
  // returns array: ["ZK-SNARKs"], ["ZK-STARKs"], or both
  const parts = splitList(v).join(' ').toLowerCase();
  if (!parts) return [];

  const out = [];
  if (parts.includes('snark')) out.push('ZK-SNARKs');
  if (parts.includes('stark')) out.push('ZK-STARKs');

  // If the CSV literally contains "both"
  if (out.length === 0 && parts.includes('both')) {
    out.push('ZK-SNARKs', 'ZK-STARKs');
  }
  return Array.from(new Set(out));
}

function escapeHtml(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function isHttpUrl(s) {
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function renderLinksHtml(urls) {
  const safe = (urls || []).filter(isHttpUrl);
  if (safe.length === 0) return '<span class="detail-value">(none)</span>';

  return safe
    .map((u, index) => {
      const label = 'Link ' + (index + 1);
      return `<a href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
    })
    .join('<br>');
}

function renderDiscardedLinksHtml(urls) {
  const safe = (urls || []).filter(isHttpUrl);
  if (safe.length === 0) return '—';

  return safe
    .map((u, index) => {
      const label = safe.length === 1 ? 'Link' : 'Link ' + (index + 1);
      return `<a href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
    })
    .join('<br>');
}

function renderDiscardedToolsTable() {
  const tbody = document.getElementById('discardedToolsTableBody');
  if (!tbody) return;

  if (!DISCARDED_TOOLS.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4" class="discarded-empty">No discarded tools available.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = DISCARDED_TOOLS.map(tool => `
    <tr>
      <td>${escapeHtml(tool.name)}</td>
      <td><span class="ic-badge">${escapeHtml(tool.icNotMeet || '—')}</span></td>
      <td>${renderDiscardedLinksHtml(tool.references)}</td>
      <td>${escapeHtml(tool.description || '—')}</td>
    </tr>
  `).join('');
}


/* ----------------------------- Column mapping ----------------------------- */
/**
 * Your CSV column names (as provided):
 * Tool Name
 * ZKP Class
 * Tool Input
 * Pipeline stages with grammar
 * Primary Analysis Approach
 * Targeted Vulnerabilities
 * Security Guarantees
 * Actively Maintained
 * Last Major Update
 * License
 * Tool References
 * Developers
 * Developers Ref
 * Usability
 * Kinds of Output
 * Academic References
 * Brief Description
 *
 * This loader supports:
 * - Headered CSV (preferred)
 * - Headerless CSV fallback by position using the order above
 */

const EXPECTED_ORDER = [
  'Tool Name',
  'ZKP Class',
  'Tool Input',
  'Pipeline stages with grammar',
  'Primary Analysis Approach',
  'Targeted Vulnerabilities',
  'Security Guarantees',
  'Actively Maintained',
  'Last Major Update',
  'License',
  'Tool References',
  'Developers',
  'Developers Ref',
  'Usability',
  'Kinds of Output',
  'Academic References',
  'Brief Description'
];

const HEADER_ALIASES = new Map([
  // canonical -> tool fields
  ['tool name', 'Tool Name'],
  ['name', 'Tool Name'],

  ['zkp class', 'ZKP Class'],
  ['zk class', 'ZKP Class'],

  ['tool input', 'Tool Input'],
  ['input', 'Tool Input'],

  ['pipeline stages with grammar', 'Pipeline stages with grammar'],
  ['pipeline stages', 'Pipeline stages with grammar'],

  ['primary analysis approach', 'Primary Analysis Approach'],
  ['analysis approach', 'Primary Analysis Approach'],

  ['targeted vulnerabilities', 'Targeted Vulnerabilities'],
  ['vulnerabilities', 'Targeted Vulnerabilities'],

  ['security guarantees', 'Security Guarantees'],
  ['guarantees', 'Security Guarantees'],

  ['actively maintained', 'Actively Maintained'],
  ['maintenance', 'Actively Maintained'],

  ['last major update', 'Last Major Update'],
  ['last update', 'Last Major Update'],

  ['license', 'License'],

  ['tool references', 'Tool References'],
  ['references', 'Tool References'],

  ['developers', 'Developers'],
  ['developer', 'Developers'],

  ['developers ref', 'Developers Ref'],
  ['developer ref', 'Developers Ref'],

  ['usability', 'Usability'],

  ['kinds of output', 'Kinds of Output'],
  ['output', 'Kinds of Output'],

  ['academic references', 'Academic References'],
  ['academic reference', 'Academic References'],

  ['brief description', 'Brief Description'],
  ['description', 'Brief Description']
]);

const DISCARDED_EXPECTED_ORDER = [
  'Tool Name',
  'IC not meet',
  'Tool References',
  'Brief Description'
];

const DISCARDED_HEADER_ALIASES = new Map([
  ['tool name', 'Tool Name'],
  ['ic not meet', 'IC not meet'],
  ['tool references', 'Tool References'],
  ['references', 'Tool References'],
  ['brief description', 'Brief Description'],
  ['description', 'Brief Description']
]);

function looksLikeHeaderRow(row) {
  const joined = row.map(c => String(c || '').toLowerCase()).join(' | ');
  return joined.includes('tool name') || joined.includes('zkp class') || joined.includes('brief description');
}

function buildRecordFromRow(header, row) {
  const record = {};

  if (header) {
    for (let i = 0; i < header.length; i++) {
      const rawKey = String(header[i] || '').trim();
      if (!rawKey) continue;

      const keyNorm = rawKey.toLowerCase().trim();
      const canonical = HEADER_ALIASES.get(keyNorm) || rawKey;
      record[canonical] = row[i] ?? '';
    }
    return record;
  }

  // Headerless fallback by expected order (truncate/ignore extras)
  for (let i = 0; i < EXPECTED_ORDER.length; i++) {
    record[EXPECTED_ORDER[i]] = row[i] ?? '';
  }
  return record;
}

function looksLikeDiscardedHeaderRow(row) {
  const joined = row.map(c => String(c || '').toLowerCase()).join(' | ');
  return joined.includes('tool name') || joined.includes('ic not meet') || joined.includes('brief description');
}

function buildDiscardedRecordFromRow(header, row) {
  const record = {};

  if (header) {
    for (let i = 0; i < header.length; i++) {
      const rawKey = String(header[i] || '').trim();
      if (!rawKey) continue;

      const keyNorm = rawKey.toLowerCase().trim();
      const canonical = DISCARDED_HEADER_ALIASES.get(keyNorm) || rawKey;
      record[canonical] = row[i] ?? '';
    }
    return record;
  }

  for (let i = 0; i < DISCARDED_EXPECTED_ORDER.length; i++) {
    record[DISCARDED_EXPECTED_ORDER[i]] = row[i] ?? '';
  }

  return record;
}

function toolFromRecord(record, id) {
  const name = normalizeEmpty(record['Tool Name']);
  const zkpClass = normalizeZkpClass(record['ZKP Class']);
  const toolInput = normalizeEmpty(record['Tool Input']);
  const pipelineStages = normalizeEmpty(record['Pipeline stages with grammar']);

  const primaryApproach = splitList(record['Primary Analysis Approach']);
  const vulnerabilities = splitList(record['Targeted Vulnerabilities']);
  const guarantees = splitList(record['Security Guarantees']);

  const maintained = normalizeMaintained(record['Actively Maintained']);
  const lastMajorUpdate = monthYearToDate(record['Last Major Update']);
  const license = normalizeEmpty(record['License']);

  const references = splitList(record['Tool References']).filter(isHttpUrl);
  const developers = splitList(record['Developers']);
  const developersRef = splitList(record['Developers Ref']).filter(isHttpUrl);

  const usabilityRaw = normalizeEmpty(record['Usability']);
  const usability = usabilityRaw !== '' && !Number.isNaN(Number(usabilityRaw)) ? Number(usabilityRaw) : null;

  const outputKinds = normalizeEmpty(record['Kinds of Output']);
  const academicRefs = normalizeEmpty(record['Academic References']);
  const description = normalizeEmpty(record['Brief Description']);

  // Skip completely empty rows
  if (!name) return null;

  return {
    id,
    name,
    zkpClass,               // string[]
    toolInput,              // string
    pipelineStages,         // string
    primaryApproach,        // string[]
    vulnerabilities,        // string[]
    guarantees,             // string[]
    maintained,             // Yes/No/Stale/...
    lastMajorUpdate,        // Date|null
    lastMajorUpdateYear: lastMajorUpdate ? String(lastMajorUpdate.getUTCFullYear()) : '',
    license,                // string
    references,             // url[]
    developers,             // string[]
    developersRef,          // url[]
    usability,              // 0/1/2/null
    outputKinds,            // string
    academicRefs,           // string
    description             // string
  };
}

function discardedToolFromRecord(record, id) {
  const name = normalizeEmpty(record['Tool Name']);
  const icNotMeet = normalizeEmpty(record['IC not meet']);
  const references = splitList(record['Tool References']).filter(isHttpUrl);
  const description = normalizeEmpty(record['Brief Description']);

  if (!name) return null;

  return {
    id,
    name,
    icNotMeet,
    references,
    description
  };
}

/* ----------------------------- App state ----------------------------- */

let TOOLS = [];           // loaded from CSV
let FILTER_OPTIONS = {};  // computed from TOOLS
let DISCARDED_TOOLS = []; // loaded from CSV
let currentView = 'tools';

// Enum-driven filters (dropdown multi-select)
const FILTER_DEFS = [
  { key: 'zkpClass', label: 'ZKP Class', extract: t => t.zkpClass },
  { key: 'primaryApproach', label: 'Primary Analysis Approach', extract: t => t.primaryApproach },
  { key: 'vulnerabilities', label: 'Targeted Vulnerabilities', extract: t => t.vulnerabilities },
  { key: 'guarantees', label: 'Security Guarantees', extract: t => t.guarantees },
  { key: 'maintained', label: 'Actively Maintained', extract: t => (t.maintained ? [t.maintained] : []) },
  { key: 'license', label: 'License', extract: t => (t.license ? [t.license] : []) },
  { key: 'usability', label: 'Usability', extract: t => (t.usability == null ? [] : [String(t.usability)]) },
  { key: 'lastMajorUpdateYear', label: 'Last Major Update (Year)', extract: t => (t.lastMajorUpdateYear ? [t.lastMajorUpdateYear] : []) }
];

let state = {
  search: '',
  filters: {},     // key -> selected[] (multi-select)
  sort: 'name-asc',
  expandedId: null
};

function initFilters() {
  FILTER_DEFS.forEach(def => {
    if (!state.filters[def.key]) state.filters[def.key] = [];
  });
}

function getFilterOptionsFromTools(tools) {
  const opts = {};
  FILTER_DEFS.forEach(def => {
    const set = new Set();
    tools.forEach(t => {
      const vals = def.extract(t) || [];
      vals.forEach(v => {
        const nv = normalizeEmpty(v);
        if (nv) set.add(nv);
      });
    });

    let arr = Array.from(set);
    // Sort usability numerically, years numerically, otherwise alpha
    if (def.key === 'usability' || def.key === 'lastMajorUpdateYear') {
      arr.sort((a, b) => Number(a) - Number(b));
    } else {
      arr.sort((a, b) => a.localeCompare(b));
    }
    opts[def.key] = arr;
  });
  return opts;
}

/* ----------------------------- Hash state ----------------------------- */

function encodeState() {
  const params = new URLSearchParams();
  if (state.search) params.set('q', state.search);
  if (state.sort !== 'name-asc') params.set('sort', state.sort);

  FILTER_DEFS.forEach(def => {
    const sel = state.filters[def.key];
    if (sel && sel.length > 0) params.set('f_' + def.key, sel.join('|'));
  });

  return params.toString();
}

function decodeState() {
  const hash = window.location.hash.slice(1);
  if (!hash) return;
  const params = new URLSearchParams(hash);

  if (params.has('q')) state.search = params.get('q') || '';
  if (params.has('sort')) state.sort = params.get('sort') || 'name-asc';

  FILTER_DEFS.forEach(def => {
    const val = params.get('f_' + def.key);
    if (val) state.filters[def.key] = val.split('|').filter(Boolean);
  });
}

function pushState() {
  window.location.hash = encodeState();
}

/* ----------------------------- Filtering & sorting ----------------------------- */

function toolToSearchableText(t) {
  const parts = [
    t.name,
    (t.developers || []).join(' '),
    (t.zkpClass || []).join(' '),
    t.toolInput,
    t.pipelineStages,
    (t.primaryApproach || []).join(' '),
    (t.vulnerabilities || []).join(' '),
    (t.guarantees || []).join(' '),
    t.maintained,
    t.lastMajorUpdateYear,
    t.license,
    (t.references || []).join(' '),
    (t.developersRef || []).join(' '),
    String(t.usability ?? ''),
    t.outputKinds,
    t.academicRefs,
    t.description
  ];
  return parts.filter(Boolean).join(' ').toLowerCase();
}

function getFilteredTools() {
  let result = TOOLS.filter(tool => {
    if (state.search) {
      const q = state.search.toLowerCase().trim();
      if (q && !toolToSearchableText(tool).includes(q)) return false;
    }

    for (const def of FILTER_DEFS) {
      const selected = state.filters[def.key];
      if (selected && selected.length > 0) {
        const vals = def.extract(tool) || [];
        // Match if ANY tool value intersects selected values
        const ok = vals.some(v => selected.includes(normalizeEmpty(v)));
        if (!ok) return false;
      }
    }

    return true;
  });

  result.sort((a, b) => {
    switch (state.sort) {
      case 'name-desc':
        return b.name.localeCompare(a.name);
      case 'assignee-asc': {
        // keep compatibility with existing HTML option name
        const da = (a.developers && a.developers[0]) ? a.developers[0] : '';
        const db = (b.developers && b.developers[0]) ? b.developers[0] : '';
        return da.localeCompare(db) || a.name.localeCompare(b.name);
      }
      case 'update-desc': {
        const ta = a.lastMajorUpdate ? a.lastMajorUpdate.getTime() : 0;
        const tb = b.lastMajorUpdate ? b.lastMajorUpdate.getTime() : 0;
        return tb - ta || a.name.localeCompare(b.name);
      }
      case 'name-asc':
      default:
        return a.name.localeCompare(b.name);
    }
  });

  return result;
}

/* ----------------------------- Rendering ----------------------------- */

function closeAllMenus(except) {
  document.querySelectorAll('.filter-menu').forEach(m => {
    if (m !== except) {
      m.classList.remove('visible');
      const btn = m.previousElementSibling;
      if (btn) {
        btn.classList.remove('open');
        btn.setAttribute('aria-expanded', 'false');
      }
    }
  });
}

function toggleFilter(key, value) {
  if (!state.filters[key]) state.filters[key] = [];
  const idx = state.filters[key].indexOf(value);
  if (idx > -1) state.filters[key].splice(idx, 1);
  else state.filters[key].push(value);

  state.expandedId = null;
  pushState();
  render();
}

function renderFilters() {
  const container = document.getElementById('filtersRow');
  container.innerHTML = '';

  FILTER_DEFS.forEach(def => {
    const selected = state.filters[def.key] || [];

    const dd = document.createElement('div');
    dd.className = 'filter-dropdown';

    const btn = document.createElement('button');
    btn.className = 'filter-button' + (selected.length > 0 ? ' active' : '');
    btn.setAttribute('aria-expanded', 'false');
    btn.setAttribute('aria-haspopup', 'listbox');
    btn.innerHTML =
      escapeHtml(def.label) +
      (selected.length > 0 ? ' <span class="filter-count">' + selected.length + '</span>' : '') +
      ' <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>';

    const menu = document.createElement('div');
    menu.className = 'filter-menu';
    menu.setAttribute('role', 'listbox');
    menu.setAttribute('aria-label', 'Filter by ' + def.label);

    (FILTER_OPTIONS[def.key] || []).forEach(opt => {
      const option = document.createElement('div');
      const isSel = selected.includes(opt);
      option.className = 'filter-option' + (isSel ? ' selected' : '');
      option.setAttribute('role', 'option');
      option.setAttribute('aria-selected', isSel ? 'true' : 'false');
      option.setAttribute('tabindex', '0');
      option.innerHTML = '<span class="filter-checkbox"></span><span>' + escapeHtml(opt) + '</span>';

      option.addEventListener('click', function (e) {
        e.stopPropagation();
        toggleFilter(def.key, opt);
      });
      option.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          toggleFilter(def.key, opt);
        }
      });

      menu.appendChild(option);
    });

    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      const isOpen = menu.classList.contains('visible');
      closeAllMenus(menu);
      if (!isOpen) {
        menu.classList.add('visible');
        btn.classList.add('open');
        btn.setAttribute('aria-expanded', 'true');
      } else {
        menu.classList.remove('visible');
        btn.classList.remove('open');
        btn.setAttribute('aria-expanded', 'false');
      }
    });

    dd.appendChild(btn);
    dd.appendChild(menu);
    container.appendChild(dd);
  });

  // close dropdowns when clicking elsewhere
  document.addEventListener('click', function () {
    closeAllMenus(null);
  });
}

function renderPills() {
  const container = document.getElementById('pillsRow');
  container.innerHTML = '';
  let hasAny = false;

  FILTER_DEFS.forEach(def => {
    const selected = state.filters[def.key] || [];
    selected.forEach(val => {
      hasAny = true;

      const pill = document.createElement('span');
      pill.className = 'pill';
      pill.innerHTML =
        '<span>' + escapeHtml(def.label) + ': ' + escapeHtml(val) + '</span>' +
        '<button aria-label="Remove filter ' + escapeHtml(val) + '">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">' +
        '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>';

      pill.querySelector('button').addEventListener('click', function () {
        toggleFilter(def.key, val);
      });

      container.appendChild(pill);
    });
  });

  if (hasAny) {
    const clearBtn = document.createElement('button');
    clearBtn.className = 'clear-all-btn';
    clearBtn.textContent = 'Clear All';
    clearBtn.addEventListener('click', function () {
      FILTER_DEFS.forEach(def => (state.filters[def.key] = []));
      state.expandedId = null;
      pushState();
      render();
    });
    container.appendChild(clearBtn);
  }
}

function formatZkpBadge(t) {
  const cls = t.zkpClass || [];
  if (cls.length === 2) return { label: 'SNARK+STARK', classTag: 'badge-stark' }; // reuse existing style
  if (cls.includes('ZK-STARKs')) return { label: 'STARK', classTag: 'badge-stark' };
  if (cls.includes('ZK-SNARKs')) return { label: 'SNARK', classTag: 'badge-snark' };
  return { label: '—', classTag: 'badge-snark' };
}

function isClosedLicense(license) {
  const t = (license || '').toLowerCase();
  return t.includes('closed');
}

function toggleToolCard(card, toolId) {
  const willExpand = !card.classList.contains('expanded');

  document.querySelectorAll('#toolsGrid .tool-card.expanded').forEach(other => {
    if (other !== card) other.classList.remove('expanded');
  });

  if (willExpand) {
    card.classList.add('expanded');
    state.expandedId = toolId;
  } else {
    card.classList.remove('expanded');
    state.expandedId = null;
  }
}

function renderPipelineStagesGraphic(pipeline) {
  const input = String(pipeline || '').trim();
  if (!input) return '—';

  const tokens = input.match(/\[\d+\]|\(\d+\)|-|=/g);
  if (!tokens || !tokens.length) return escapeHtml(input);

  const parts = tokens.map(token => {
    if (/^\[\d+\]$/.test(token) || /^\(\d+\)$/.test(token)) {
      const stage = token.replace(/\D/g, '');
      const active = token.startsWith('[');

      return `
        <span
          title="${active ? 'Used in stage ' : 'Not used in stage '}${stage}"
          aria-label="${active ? 'Used in stage ' : 'Not used in stage '}${stage}"
          style="
            display:inline-flex;
            align-items:center;
            justify-content:center;
            width:1.28em;
            height:1.28em;
            font:700 0.68rem/1 system-ui,sans-serif;
            border-radius:999px;
            border:1.2px solid ${active ? '#2563eb' : '#94a3b8'};
            background:${active ? '#2563eb' : 'transparent'};
            color:${active ? '#ffffff' : '#475569'};
            box-sizing:border-box;
            flex:0 0 auto;
          "
        >${stage}</span>
      `;
    }

    const activeTransition = token === '-';

    return `
      <span
        title="${activeTransition ? 'Used in transition' : 'No transition'}"
        aria-hidden="true"
        style="
          display:inline-block;
          width:${activeTransition ? '0.95em' : '0.78em'};
          height:0;
          border-top:${activeTransition ? '3.6px solid #2563eb' : '1.2px solid #cbd5e1'};
          opacity:${activeTransition ? '1' : '0.75'};
          margin:0 0.015em;
          flex:0 0 auto;
        "
      ></span>
    `;
  });

  return `
    <span
      class="pipeline-graphic"
      aria-label="Pipeline stages ${escapeHtml(input)}"
      style="
        display:inline-flex;
        align-items:center;
        gap:0;
        white-space:nowrap;
        vertical-align:middle;
      "
    >
      ${parts.join('')}
    </span>
  `;
}

function renderCards(tools) {
  const grid = document.getElementById('toolsGrid');

  if (tools.length === 0) {
    grid.innerHTML =
      '<div class="empty-state">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
      '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/><line x1="8" y1="11" x2="14" y2="11"/></svg>' +
      '<h3>No tools match your filters</h3><p>Try adjusting your search query or removing some filters to see more results.</p></div>';
    return;
  }

  grid.innerHTML = '';
  tools.forEach(tool => {
    const isExpanded = state.expandedId === tool.id;
    const card = document.createElement('article');
    card.className = 'tool-card' + (isExpanded ? ' expanded' : '');
    card.setAttribute('role', 'listitem');
    card.setAttribute('tabindex', '0');
    card.setAttribute('aria-label', tool.name);

    const badge = formatZkpBadge(tool);

    const licenseIsOpen = !isClosedLicense(tool.license);
    const licenseTag = licenseIsOpen ? 'badge-open' : 'badge-closed';

    const statusLabel = tool.maintained || 'Unknown';
    const statusDotClass =
      statusLabel === 'Yes' ? 'maintained' : (statusLabel === 'Stale' ? 'not-maintained' : 'not-maintained');

    const devShort = (tool.developers && tool.developers.length > 0)
      ? tool.developers.slice(0, 2).join(', ') + (tool.developers.length > 2 ? '…' : '')
      : '—';

    const tags = [];
    if (tool.toolInput) {
      var separateToolInputs = tool.toolInput.split(/\r?\n|\r|\n/g);
      separateToolInputs.forEach(toolInput => {
        tags.push(toolInput);
      });
    }
    //if (tool.primaryApproach && tool.primaryApproach.length) tags.push(tool.primaryApproach[0]);
    //if (tool.outputKinds) tags.push(tool.outputKinds);

    let html =
      '<div class="card-header">' +
      '<div>' +
      '<div class="tool-name">' + escapeHtml(tool.name) + '</div>' +
      '<div class="tool-assignee">' + escapeHtml(devShort) + '</div>' +
      '</div>' +
      '<span class="badge ' + badge.classTag + '">' + escapeHtml(badge.label) + '</span>' +
      '</div>';

    html += '<div class="card-tags">' +
      tags.slice(0, 3).map(t => '<span class="tag">' + escapeHtml(t) + '</span>').join('') +
      '</div>';

    html += '<div class="card-description">' + escapeHtml(tool.description || '') + '</div>';

    html += '<div class="card-footer">' +
      '<span class="status-indicator"><span class="status-dot ' + statusDotClass + '" aria-hidden="true"></span>' +
      'Maintained: ' + escapeHtml(statusLabel) +
      '</span>' +
      '<span class="badge ' + licenseTag + '">' + escapeHtml(licenseIsOpen ? 'Open Source' : 'Closed Source') + '</span>' +
      '</div>';

    html += '<div class="expanded-details"><div class="detail-grid">';

    html += '<div class="detail-item"><div class="detail-label">Tool Name</div><div class="detail-value">' + escapeHtml(tool.name) + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">ZKP Class</div><div class="detail-value">' + escapeHtml((tool.zkpClass || []).join(', ') || '—') + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">Tool Input</div><div class="detail-value">' + escapeHtml(separateToolInputs.join(", ") || '—') + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">Pipeline Stages</div><div class="detail-value">' + renderPipelineStagesGraphic(tool.pipelineStages || '—') + '</div></div>';

    html += '<div class="detail-item"><div class="detail-label">Primary Analysis Approach</div><div class="detail-value">' + escapeHtml((tool.primaryApproach || []).join(', ') || '—') + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">Targeted Vulnerabilities</div><div class="detail-value">' + escapeHtml((tool.vulnerabilities || []).join(', ') || '—') + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">Security Guarantees</div><div class="detail-value">' + escapeHtml((tool.guarantees || []).join(', ') || '—') + '</div></div>';

    html += '<div class="detail-item"><div class="detail-label">Actively Maintained</div><div class="detail-value">' + escapeHtml(tool.maintained || '—') + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">Last Major Update</div><div class="detail-value">' + escapeHtml(tool.lastMajorUpdateYear || '—') + '</div></div>';

    html += '<div class="detail-item"><div class="detail-label">License</div><div class="detail-value">' + escapeHtml(tool.license || '—') + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">Usability</div><div class="detail-value">' + renderUsabilityGraphic(tool.usability) + '</div></div>';

    html += '<div class="detail-item"><div class="detail-label">Kinds of Output</div><div class="detail-value">' + escapeHtml(tool.outputKinds || '—') + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">Academic References</div><div class="detail-value">' + escapeHtml(tool.academicRefs || '—') + '</div></div>';

    html += '<div class="detail-item"><div class="detail-label">Developers</div><div class="detail-value">' + escapeHtml((tool.developers || []).join(', ') || '—') + '</div></div>';

    html += '<div class="detail-item"><div class="detail-label">Tool References</div><div class="detail-value">' + renderLinksHtml(tool.references) + '</div></div>';
    html += '<div class="detail-item"><div class="detail-label">Developers Ref</div><div class="detail-value">' + renderLinksHtml(tool.developersRef) + '</div></div>';

    html += '</div></div>';

    card.innerHTML = html;

    card.addEventListener('click', function (e) {
      if (e.target.closest('a, button')) return;
      toggleToolCard(card, tool.id);
    });

    card.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleToolCard(card, tool.id);
      }
    });

    grid.appendChild(card);
  });
}

function renderUsabilityGraphic(value) {
  if (value == null || value === '') return '—';

  const n = Number(value);
  if (![0, 1, 2].includes(n)) return escapeHtml(String(value));

  const symbol = n === 0 ? '◯' : (n === 1 ? '◐' : '⬤');
  const textual = n === 0 ? 'little' : (n === 1 ? 'medium' : 'high');

  return `
    <span
      title="Usability: ${n} (${textual})"
      aria-label="Usability ${n}"
      style="
        display:inline-flex;
        align-items:center;
        gap:0.4em;
        white-space:nowrap;
      "
    >
      <span
        style="
          font-size:1.05em;
          line-height:1;
          color:#2563eb;
        "
      >${symbol}</span>
      <span>(${textual})</span>
    </span>
  `;
}

function render() {
  renderFilters();
  renderPills();

  const filtered = getFilteredTools();
  const resultsCount = document.getElementById('resultsCount');
  if (resultsCount) {
    resultsCount.innerHTML = 'Showing <strong>' + filtered.length + '</strong> of <strong>' + TOOLS.length + '</strong> tools';
  }

  renderCards(filtered);
  renderDiscardedToolsTable();

  const totalToolCount = document.getElementById('totalToolCount');
  if (totalToolCount) totalToolCount.textContent = TOOLS.length + ' Tools';

  const discardedToolCount = document.getElementById('discardedToolCount');
  if (discardedToolCount) {
    discardedToolCount.textContent = DISCARDED_TOOLS.length + ' Discarded Tools';
  }

  syncViewUI();
}

/* ----------------------------- Controls ----------------------------- */

function onSearchInput(e) {
  state.search = e.target.value || '';
  state.expandedId = null;
  pushState();
  render();
}

function onSortChange(e) {
  state.sort = e.target.value;
  state.expandedId = null;
  pushState();
  render();
}

/* ----------------------------- Theme + scroll (kept compatible) ----------------------------- */

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);

  const sun = document.getElementById('sunIcon');
  const moon = document.getElementById('moonIcon');
  if (sun && moon) {
    const isDark = theme === 'dark';
    sun.style.display = isDark ? 'none' : '';
    moon.style.display = isDark ? '' : 'none';
  }
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || 'light';
  setTheme(cur === 'dark' ? 'light' : 'dark');
}

function handleScroll() {
  const btn = document.getElementById('scrollTopBtn');
  if (!btn) return;
  btn.classList.toggle('visible', window.scrollY > 600);
}

function scrollToTop() {
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ----------------------------- Data load ----------------------------- */

async function loadToolsFromCSV(url) {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error('Failed to fetch ' + url + ' (HTTP ' + res.status + ')');
  const text = await res.text();

  const rows = parseCSV(text);
  if (!rows || rows.length === 0) return [];

  let header = null;
  let startIdx = 0;

  if (looksLikeHeaderRow(rows[0])) {
    header = rows[0].map(h => String(h || '').trim());
    startIdx = 1;
  }

  const tools = [];
  let id = 1;

  for (let i = startIdx; i < rows.length; i++) {
    const record = buildRecordFromRow(header, rows[i]);
    const tool = toolFromRecord(record, id);
    if (tool) {
      tools.push(tool);
      id++;
    }
  }

  return tools;
}

async function loadDiscardedToolsFromCSV(url) {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error('Failed to fetch ' + url + ' (HTTP ' + res.status + ')');

  const text = await res.text();
  const rows = parseCSV(text);
  if (!rows || rows.length === 0) return [];

  let header = null;
  let startIdx = 0;

  if (looksLikeDiscardedHeaderRow(rows[0])) {
    header = rows[0].map(h => String(h || '').trim());
    startIdx = 1;
  }

  const tools = [];
  let id = 1;

  for (let i = startIdx; i < rows.length; i++) {
    const record = buildDiscardedRecordFromRow(header, rows[i]);
    const tool = discardedToolFromRecord(record, id);
    if (tool) {
      tools.push(tool);
      id++;
    }
  }

  return tools;
}

function syncViewUI() {
  const toolsSection = document.getElementById('toolsSection');
  const discardedSection = document.getElementById('discardedSection');
  const toolsBadge = document.getElementById('toolsViewBadge');
  const discardedBadge = document.getElementById('discardedViewBadge');

  const showingTools = currentView === 'tools';

  if (toolsSection) toolsSection.hidden = !showingTools;
  if (discardedSection) discardedSection.hidden = showingTools;

  if (toolsBadge) {
    toolsBadge.classList.toggle('is-active', showingTools);
    toolsBadge.classList.toggle('is-inactive', !showingTools);
    toolsBadge.setAttribute('aria-pressed', showingTools ? 'true' : 'false');
  }

  if (discardedBadge) {
    discardedBadge.classList.toggle('is-active', !showingTools);
    discardedBadge.classList.toggle('is-inactive', showingTools);
    discardedBadge.setAttribute('aria-pressed', showingTools ? 'false' : 'true');
  }

  closeAllMenus(null);
}

function setView(view) {
  currentView = view === 'discarded' ? 'discarded' : 'tools';
  syncViewUI();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ----------------------------- Boot ----------------------------- */

document.addEventListener('DOMContentLoaded', async function () {
  // initial theme
  const saved = localStorage.getItem('theme');
  setTheme(saved || 'light');

  // add an extra sort option (optional, non-breaking)
  const sortSelect = document.getElementById('sortSelect');
  if (sortSelect && !Array.from(sortSelect.options).some(o => o.value === 'update-desc')) {
    const opt = document.createElement('option');
    opt.value = 'update-desc';
    opt.textContent = 'Last Update (Newest)';
    sortSelect.appendChild(opt);
  }

  // wire events
  document.getElementById('searchInput').addEventListener('input', onSearchInput);
  document.getElementById('sortSelect').addEventListener('change', onSortChange);
  document.getElementById('themeToggle').addEventListener('click', toggleTheme);
  document.getElementById('scrollTopBtn').addEventListener('click', scrollToTop);
  window.addEventListener('scroll', handleScroll, { passive: true });

  const toolsViewBadge = document.getElementById('toolsViewBadge');
  if (toolsViewBadge) {
    toolsViewBadge.addEventListener('click', function () {
      setView('tools');
    });
  }

  const discardedViewBadge = document.getElementById('discardedViewBadge');
  if (discardedViewBadge) {
    discardedViewBadge.addEventListener('click', function () {
      setView('discarded');
    });
  }

  initFilters();
  decodeState();

  // loading UI
  document.getElementById('resultsCount').textContent = 'Loading tools from data.csv…';

  try {
    const [tools, discardedTools] = await Promise.all([
      loadToolsFromCSV('data.csv'),
      loadDiscardedToolsFromCSV('discarded.csv')
    ]);
    TOOLS = tools;
    DISCARDED_TOOLS = discardedTools;
    FILTER_OPTIONS = getFilterOptionsFromTools(TOOLS);

    // Ensure any decoded filters only keep values that exist (avoid dead hash states)
    FILTER_DEFS.forEach(def => {
      const valid = new Set(FILTER_OPTIONS[def.key] || []);
      state.filters[def.key] = (state.filters[def.key] || []).filter(v => valid.has(v));
    });

    // apply decoded search/sort to UI
    document.getElementById('searchInput').value = state.search || '';
    document.getElementById('sortSelect').value = state.sort || 'name-asc';

    render();
  } catch (err) {
    console.error(err);
    document.getElementById('resultsCount').textContent =
      'Error loading data.csv. If you opened the file directly, run a local server instead of file://';
    document.getElementById('toolsGrid').innerHTML =
      '<div class="empty-state"><h3>Failed to load data.csv</h3><p>' +
      escapeHtml(err.message || String(err)) +
      '</p></div>';
  }
});