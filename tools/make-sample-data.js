/*
 * Writes the files in sample-data/ used to demonstrate import and its error cases.
 * Run from the project folder:  node tools/make-sample-data.js
 */
const fs = require('fs');
const path = require('path');
const demo = require('../js/demo-data.js');

const out = path.join(__dirname, '..', 'sample-data');
const sample = demo.buildImportSample();
const ndjson = (records) => records.map((r) => JSON.stringify(r)).join('\n') + '\n';

// 1. A clean export in the same shape as /var/ossec/logs/alerts/alerts.json (one alert per line).
fs.writeFileSync(path.join(out, '1-valid-alerts.json'), ndjson(sample));

// 2. The same export with three damaged records: no rule, no timestamp, and a line that is not JSON.
const partial = sample.slice(0, 12).map((r) => JSON.stringify(r));
const noRule = Object.assign({}, sample[12]); delete noRule.rule;
const noTime = Object.assign({}, sample[13]); delete noTime.timestamp;
partial.splice(4, 0, JSON.stringify(noRule));
partial.splice(8, 0, JSON.stringify(noTime));
partial.push('{"timestamp": "2026-11-15T03:06:00.000+0500", "rule": {"level": 5, "descr');
fs.writeFileSync(path.join(out, '2-partly-damaged-alerts.json'), partial.join('\n') + '\n');

// 3. A file that was cut off mid-transfer: not valid JSON at all.
fs.writeFileSync(path.join(out, '3-broken-file.json'), JSON.stringify(sample.slice(0, 3), null, 2).slice(0, 700));

// 4. An empty file.
fs.writeFileSync(path.join(out, '4-empty-file.json'), '');

// 5. Valid JSON that has nothing to do with Wazuh alerts.
fs.writeFileSync(path.join(out, '5-not-wazuh-alerts.json'), JSON.stringify({ name: 'inventory', items: [{ sku: 'A-1', qty: 4 }, { sku: 'B-7', qty: 0 }] }, null, 2));

console.log('sample-data written:', fs.readdirSync(out).join(', '));
