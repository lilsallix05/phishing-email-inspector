'use strict';
const $ = selector => document.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const defang = value => String(value ?? '').replace(/https?:\/\//gi, s => s.replace('http','hxxp')).replace(/\./g,'[.]');
let session = '', samples = [], result = null, evaluation = null, rawBytes = null;
let busy = false, inputVersion = 0, resultVersion = -1, requestSerial = 0, activeRequest = null;
let activeView = 'inspect', sourceLabel = 'Import or paste', resultLabel = '';
const scrollPositions = {}, empty = $('#report').innerHTML;

async function request(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw Error(data.error || 'The local service could not complete this request.');
  return data;
}
function error(message) {
  $('#error').hidden = !message;
  $('#error').textContent = message || '';
}
function canExport() { return Boolean(result) && resultVersion === inputVersion && !busy; }
function updateReportState() {
  const note = $('#report-status');
  if (note) {
    note.hidden = canExport();
    note.textContent = busy ? 'Inspecting the current source. Report and exports will update when it finishes.' : 'Previous report. Inspect the current source to update it and enable exports.';
  }
  ['#export-report', '#export-links'].forEach(id => { if ($(id)) $(id).disabled = !canExport(); });
}
function setBusy(value) {
  busy = value;
  $('#analyze').disabled = value;
  $('#analyze').textContent = value ? 'Inspecting…' : 'Inspect this email';
  updateReportState();
}
function sourceChanged(label) {
  inputVersion += 1;
  requestSerial += 1;
  if (activeRequest) activeRequest.controller.abort();
  activeRequest = null;
  sourceLabel = label;
  $('#source-summary').textContent = label;
  setBusy(false);
  error('');
  return inputVersion;
}
function download(data, name, type = 'application/json') {
  const blob = new Blob([typeof data === 'string' ? data : JSON.stringify(data, null, 2)], {type});
  const url = URL.createObjectURL(blob), anchor = document.createElement('a');
  anchor.href = url; anchor.download = name; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function nav(view) {
  scrollPositions[activeView] = window.scrollY;
  activeView = view;
  document.querySelectorAll('.view').forEach(el => { el.hidden = el.id !== view; });
  document.querySelectorAll('.nav').forEach(button => {
    button.classList.toggle('active', button.dataset.view === view);
    if (button.dataset.view === view) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  requestAnimationFrame(() => window.scrollTo(0, scrollPositions[view] || 0));
  if (view === 'monitor') loadAlerts();
}
document.querySelectorAll('.nav').forEach(button => { button.onclick = () => nav(button.dataset.view); });
$('#clear').onclick = () => {
  sourceChanged('Import or paste');
  $('#raw').value = ''; $('#file').value = ''; rawBytes = null; result = null; resultVersion = -1;
  $('#report').innerHTML = empty; $('#source-panel').open = true;
  $('#file-status').textContent = 'Original bytes stay on this device.';
  $('#raw').focus();
};
$('#raw').oninput = () => {
  rawBytes = null;
  sourceChanged('Pasted source');
  $('#file-status').textContent = 'Edited source will be analyzed as UTF-8.';
};
async function importFile(file) {
  if (!file) return;
  const version = sourceChanged('Importing ' + file.name);
  if (file.size > 2 * 1024 * 1024) { error('Choose one email smaller than 2 MiB.'); return; }
  if (!file.name.toLowerCase().endsWith('.eml')) { error('Choose an .eml file exported from your email client.'); return; }
  setBusy(true); $('#analyze').textContent = 'Reading file…';
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (version !== inputVersion) return;
    let binary = '';
    for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    rawBytes = btoa(binary); $('#raw').value = new TextDecoder().decode(bytes);
    sourceLabel = file.name; $('#source-summary').textContent = sourceLabel;
    $('#file-status').textContent = `${file.size.toLocaleString()} bytes; original bytes preserved`;
  } catch (_) {
    if (version === inputVersion) error('The file could not be read. Choose it again or paste the email source.');
  } finally {
    if (version === inputVersion) setBusy(false);
  }
}
$('#file').onchange = () => importFile($('#file').files[0]);
['dragenter','dragover'].forEach(event => $('#drop').addEventListener(event, e => { e.preventDefault(); $('#drop').classList.add('drag'); }));
['dragleave','drop'].forEach(event => $('#drop').addEventListener(event, e => {
  e.preventDefault(); $('#drop').classList.remove('drag');
  if (event === 'drop') importFile(e.dataTransfer.files[0]);
}));
$('#analyze').onclick = async () => {
  if (busy) return;
  error('');
  if (!$('#raw').value.trim()) { error('Import an .eml file or paste the original email source first.'); return; }
  const version = inputVersion, serial = ++requestSerial, label = sourceLabel;
  const controller = new AbortController();
  activeRequest = {serial, controller}; resultVersion = -1; setBusy(true);
  const payload = rawBytes ? {raw_base64: rawBytes} : {raw: $('#raw').value};
  try {
    const completed = await request('/api/analyze', {
      method: 'POST', headers: {'Content-Type':'application/json','X-Inspection-Token':session},
      body: JSON.stringify(payload), signal: controller.signal
    });
    if (version !== inputVersion || serial !== requestSerial) return;
    result = completed; resultVersion = version; resultLabel = label;
    renderResult();
    if (window.matchMedia('(max-width: 760px)').matches) {
      $('#source-panel').open = false;
      $('#report').focus({preventScroll:true});
      $('#report').scrollIntoView({block:'start'});
    }
  } catch (e) {
    if (version === inputVersion && serial === requestSerial && e.name !== 'AbortError') {
      error(e.message); $('#source-panel').open = true;
    }
  } finally {
    if (serial === requestSerial) { activeRequest = null; setBusy(false); }
  }
};

function renderResult() {
  const m = result.message, r = result.rules;
  $('#report').innerHTML = `<div id="report-status" class="status-note" role="status" hidden></div>
    <div class="result-head">${resultLabel.startsWith('Synthetic') ? '<p class="fine provenance">Synthetic example</p>' : ''}
      <h2 class="subject">${esc(m.subject)}</h2><div class="from">${esc(m.from.map(f => `${f.name} <${f.address}>`).join(', ') || 'No usable sender')}</div>
      <div class="assessment"><div class="score ${r.score >= 55 ? 'high' : r.score < 20 ? 'low' : ''}">${r.score}<small>/ 100 points</small></div>
      <div><h3>${esc(r.level)}</h3><p>${r.findings.length} signals, ${m.links.length} link entries, ${m.attachments.length} attachments</p></div></div>
      <p class="result-limit">Triage points, not a probability. A low score does not establish safety.</p>
      <div class="report-actions"><button class="secondary" id="export-report">Export report JSON</button><button class="secondary" id="export-links">Export link evidence CSV</button></div>
    </div><div class="report-tabs" role="tablist" aria-label="Report sections">${['Signals','Message','Links','Headers','Model'].map((tab,i) => `<button role="tab" id="tab-${tab}" aria-controls="report-body" aria-selected="${!i}" tabindex="${i ? -1 : 0}" class="${i ? '' : 'active'}" data-tab="${tab}">${tab}${tab === 'Links' ? ' (' + m.links.length + ')' : ''}</button>`).join('')}</div>
    <div class="report-body" id="report-body" role="tabpanel" aria-labelledby="tab-Signals"></div>`;
  $('#export-report').onclick = () => { if (canExport()) download(result, 'postmark-report-' + m.sha256.slice(0,10) + '.json'); };
  $('#export-links').onclick = () => {
    if (!canExport()) return;
    const cell = value => '"' + (' ' + String(value ?? '')).replace(/"/g,'""') + '"';
    download(['display,destination,host,issues', ...m.links.map(link => [defang(link.display),defang(link.url),defang(link.host),link.issues.join('; ')].map(cell).join(','))].join('\r\n'), 'postmark-links.csv', 'text/csv');
  };
  document.querySelectorAll('[data-tab]').forEach(button => {
    button.onclick = () => reportTab(button.dataset.tab);
    button.onkeydown = event => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
      event.preventDefault(); const buttons = [...document.querySelectorAll('[data-tab]')];
      const next = buttons[(buttons.indexOf(button) + (event.key === 'ArrowRight' ? 1 : buttons.length - 1)) % buttons.length];
      next.click(); next.focus();
    };
  });
  reportTab('Signals'); updateReportState();
}
function reportTab(tab) {
  const m = result.message, r = result.rules;
  document.querySelectorAll('[data-tab]').forEach(button => {
    const selected = button.dataset.tab === tab;
    button.classList.toggle('active',selected); button.setAttribute('aria-selected',selected); button.tabIndex = selected ? 0 : -1;
  });
  $('#report-body').setAttribute('aria-labelledby','tab-' + tab);
  let html = '';
  if (tab === 'Signals') html = `<div class="notice warning">${r.score >= 20 ? 'Verify unusual requests through a known contact or official app.' : 'Few rule signals found. Unfamiliar phishing can still look ordinary.'}</div>` + r.findings.map(f => `<section class="finding"><div class="finding-head"><h3>${esc(f.title)}</h3><span class="points">${f.weight ? '+ ' + f.weight + ' points' : 'Coverage note'}</span></div><code class="evidence">${esc(defang(f.evidence))}</code><p>${esc(f.explanation)}</p><div class="action">${esc(f.action)}</div></section>`).join('') + `<details class="disclosure"><summary>How points are calculated</summary><p>${esc(r.score_meaning)}</p></details>`;
  if (tab === 'Message') html = `<div class="notice">Text extraction only. ${m.remote_images} remote images skipped; attachments unopened.</div><div class="body-text">${esc(m.body || 'No readable text body found.')}</div><h3>Attachment metadata</h3>${m.attachments.length ? m.attachments.map(a => `<p class="fine"><strong>${esc(a.name)}</strong><br>${esc(a.type)}, ${a.bytes} decoded bytes</p>`).join('') : '<p class="fine">No attachments found.</p>'}`;
  if (tab === 'Links') html = '<div class="notice">Inert, defanged links. Destinations and reputation are unverified.</div>' + (m.links.length ? m.links.map(link => `<section class="link-row"><small>Displayed text</small><div>${esc(defang(link.display))}</div><small>Actual destination</small><code class="evidence">${esc(defang(link.url))}</code><small>Parsed host: ${esc(defang(link.host) || '(none)')}</small>${link.issues.map(issue => `<div class="flag">${esc(issue)}</div>`).join('')}${!link.issues.length ? '<p class="fine">No URL pattern signal. Destination is still unverified.</p>' : ''}</section>`).join('') : '<p>No links found in inspected text.</p>') + '<details class="disclosure"><summary>Host comparison limits</summary><p>Hosts are compared exactly. Different subdomains can be legitimate. Redirects are not followed and domain ownership is not verified.</p></details>';
  if (tab === 'Headers') html = '<div class="notice">Imported authentication headers are untrusted. SPF, DKIM and DMARC are not verified.</div><dl class="meta">' + Object.entries(m.headers).map(([key,values]) => `<dt>${esc(key)}</dt><dd>${values.length ? values.map(esc).join('<br>') : '—'}</dd>`).join('') + `<dt>SHA-256</dt><dd>${esc(m.sha256)}</dd><dt>Parser defects</dt><dd>${esc(m.defects.join(', ') || 'None reported')}</dd><dt>Coverage</dt><dd>${m.truncated ? 'Limited; review original' : 'Within local limits'}</dd></dl>`;
  if (tab === 'Model') {
    const model = result.model;
    html = `<div class="notice warning"><strong>Synthetic-trained.</strong> No real inbox validation; score is uncalibrated.</div><h3>Model label: ${esc(model.label)}</h3><p class="fine">Output ${model.score.toFixed(4)} at threshold 0.5. ${model.known_tokens} known tokens.</p><div class="table-wrap" role="region" aria-label="Model token contributions" tabindex="0"><table><thead><tr><th>Token</th><th>Log odds</th><th>Direction</th></tr></thead><tbody>${model.top_features.map(f => `<tr><td>${esc(f.token)}</td><td>${f.log_odds}</td><td>${esc(f.direction)}</td></tr>`).join('')}</tbody></table></div><details class="disclosure"><summary>Read the token contributions</summary><p>These are the largest model contributions for this message. Positive log odds push toward phishing; negative values push toward benign. They explain the model calculation, not the sender’s intent.</p></details><button class="quiet" id="model-evidence">View held-out mistakes</button>`;
  }
  $('#report-body').innerHTML = html;
  if ($('#model-evidence')) $('#model-evidence').onclick = () => nav('evaluation');
}
function renderEvaluation(data) {
  evaluation = data;
  const metrics = data.model_metrics, wrong = data.predictions.filter(p => p.label !== p.prediction);
  $('#evaluation-content').innerHTML = `<div class="notice warning"><strong>Synthetic evaluation only.</strong> No real inbox validation. Shared author assumptions favor the rules.</div>
    <div class="metrics">${[['Precision',(metrics.precision*100).toFixed(1)+'%'],['Recall',(metrics.recall*100).toFixed(1)+'%'],['False positive rate',(metrics.false_positive_rate*100).toFixed(1)+'%'],['Held-out emails',data.test_rows]].map(([name,value]) => `<div class="metric"><b>${value}</b><span>${name}</span></div>`).join('')}</div>
    <div class="eval-columns"><div><h2>Confusion matrix</h2><p class="fine">Rows: assigned labels. Columns: predictions.</p><table class="matrix"><thead><tr><th></th><th>Predicted phishing</th><th>Predicted benign</th></tr></thead><tbody><tr><th>Actual phishing</th><td data-prediction="Predicted phishing">${metrics.true_positive}<small>True positives</small></td><td data-prediction="Predicted benign">${metrics.false_negative}<small>False negatives</small></td></tr><tr><th>Actual benign</th><td data-prediction="Predicted phishing">${metrics.false_positive}<small>False positives</small></td><td data-prediction="Predicted benign">${metrics.true_negative}<small>True negatives</small></td></tr></tbody></table></div>
    <div><h2>${wrong.length} model errors</h2><p class="fine">False positives retained for review.</p><ul class="error-list">${wrong.map(p => `<li><div><code>${esc(p.id)}</code><small>Assigned ${esc(p.label)}; predicted ${esc(p.prediction)}</small></div><span class="error-output">${p.score.toFixed(4)}</span></li>`).join('')}</ul></div></div>
    <details class="disclosure"><summary>Split method and validation limits</summary><p>${esc(data.dataset)}.</p><p>${esc(data.split)}</p><dl class="meta"><dt>Training</dt><dd>${data.training_rows} emails, ${data.training_families.length} families</dd><dt>Holdout</dt><dd>${data.test_rows} emails, ${data.test_families.length} families</dd><dt>Family overlap</dt><dd>${data.family_overlap}</dd><dt>Duplicate overlap</dt><dd>${data.canonical_duplicate_overlap}</dd></dl><p>A real evaluation requires consented, licensed, independently labeled emails and a fresh holdout grouped by campaign, sender, time and duplicates. Multilingual coverage and adversarial robustness remain unvalidated.</p></details>
    <details class="disclosure"><summary>Rule-only comparison</summary><p>At ${data.rules_threshold} points, rules returned ${data.rules_metrics.true_positive} true positives, ${data.rules_metrics.false_positive} false positives, ${data.rules_metrics.true_negative} true negatives, and ${data.rules_metrics.false_negative} false negatives on the same synthetic holdout. The authored scenarios favor these rules; this is not independent real-world detection evidence.</p></details>`;
}
$('#export-eval').onclick = () => { if (evaluation) download(evaluation,'postmark-evaluation.json'); };
let watchBusy = false;
async function loadAlerts() {
  if (watchBusy) return;
  watchBusy = true; $('#refresh-alerts').disabled = true; $('#refresh-alerts').textContent = 'Refreshing…';
  try {
    const data = await request('/api/alerts');
    $('#watch-status').innerHTML = `<h2>${esc(data.mode)}</h2><p class="fine">${data.last_checked ? 'Last check: ' + esc(new Date(data.last_checked).toLocaleString()) : 'No observations yet.'}</p>`;
    $('#alerts').innerHTML = data.alerts.length ? data.alerts.map(alert => `<section class="watch-entry"><h3>${esc(alert.level)} (${alert.score} points)</h3><div class="watch-reference">Message reference <code>${esc(alert.id)}</code></div><p>${alert.findings.map(esc).join('; ') || 'No rule signals.'}</p></section>`).join('') : '<p>Run the local fixture below, or connect an authorized test mailbox using docs/MAILBOX-ADAPTERS.md.</p>';
  } catch (e) {
    $('#watch-status').textContent = 'Refresh failed. Previous observations are retained. ' + e.message;
  } finally {
    watchBusy = false; $('#refresh-alerts').disabled = false; $('#refresh-alerts').textContent = 'Refresh observations';
  }
}
(async () => {
  try {
    const localSession = await request('/api/session'); session = localSession.token;
    samples = await request('/api/samples');
    $('#samples').innerHTML = samples.map((sample,i) => `<button data-sample="${i}">${esc(sample.name)}</button>`).join('');
    document.querySelectorAll('[data-sample]').forEach(button => {
      button.onclick = () => {
        const sample = samples[Number(button.dataset.sample)];
        sourceChanged('Synthetic example: ' + sample.name);
        $('#file').value = ''; $('#raw').value = sample.raw; rawBytes = null;
        $('#file-status').textContent = 'Synthetic fixture ' + sample.id;
        $('#analyze').click();
      };
    });
    renderEvaluation(await request('/api/evaluation'));
  } catch (e) { error('Start python3 server.py and reload. ' + e.message); }
})();
$('#refresh-alerts').onclick = loadAlerts;
