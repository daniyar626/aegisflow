# AegisFlow MVP

Human-controlled first-pass triage of Wazuh security alerts.
Group CS-2419: Maratov Daniyar, Dossymzhan Sheri, Yedil Mukash.

**Live demo:** https://daniyar626.github.io/aegisflow/

AegisFlow reads raw Wazuh alerts, groups them into cases, explains each verdict with the evidence behind it, and records the decision that a named person makes. It never blocks or changes anything by itself. The interface works in English and Kazakh.

## Run it

**On your computer.** Open `index.html` in Chrome, Edge or Firefox. Nothing has to be installed.

**As a local web server** (closer to the hosted version):

```bash
python -m http.server 5173
```

Then open `http://localhost:5173`.

**Online (needed for the exam link).** The site is a folder of static files, so any static host works for free:

- Netlify Drop: open `https://app.netlify.com/drop` and drag the `AegisFlow-MVP` folder onto the page. It returns a public URL.
- GitHub Pages: push the folder contents to a repository, then Settings, Pages, deploy from the main branch.

There is no login and no test account. The reviewer types a name, and that name is written into the audit log.

## Core journey

1. **Data source.** Enter your name, then load the Wazuh lab dataset or import your own `alerts.json`.
2. **Alert queue.** 211 alerts appear as 11 cases, most severe first, each with a verdict and a confidence level.
3. **Case.** Read what happened in plain language, why the verdict was reached (every point of the score is listed), and the evidence timeline. Any row opens the raw Wazuh record.
4. **Decision.** Approve the recommended action, dismiss the case as a false positive, or escalate it. Approval needs a name and a confirmation that the evidence was reviewed.
5. **Outcome.** The decision is stamped, an action ticket is produced for the firewall or host administrator, and the audit log gets an entry with a SHA-256 fingerprint of the evidence.
6. **Feedback.** Rate the case as useful or not, give a trust score from 1 to 5, and leave a comment. The session report shows time to decision and ratings.

## Demonstration script for the defence (about 4 minutes)

| Step | What to do | What it shows |
|---|---|---|
| 1 | In English: type a name, press **Load lab dataset** | Entry point, privacy notice |
| 2 | Point at the queue: 211 alerts, 11 cases | Noise reduction, prioritisation |
| 3 | Open the top case (password guessing followed by a successful login) | Plain-language summary, score, evidence |
| 4 | Press **Show 143 alerts**, open **List the alerts** | Every claim links to raw records |
| 5 | Press **Approve action**, tick the box, confirm | Human approval, stamp, action ticket |
| 6 | Switch to **ҚАЗ** and open **Дабылдар кезегі** | Full Kazakh interface, including generated summaries |
| 7 | In Kazakh: open the web attack case, dismiss or escalate it | Core journey in the second language |
| 8 | Boundary case: on **Data source**, upload `sample-data/3-broken-file.json` | Invalid input is refused with a clear message |
| 9 | Optional: **Settings**, turn on the reputation feed outage, reopen the web attack case | Verdict drops from likely malicious to needs review, confidence drops, the case still works |
| 10 | Open **Audit log** and **Session report** | Named decisions, evidence fingerprint, time to decision |

## Boundary and failure cases

| Situation | How to trigger it | What AegisFlow does |
|---|---|---|
| Empty file | Upload `sample-data/4-empty-file.json` | Explains that the file is empty; current data stays untouched |
| Broken JSON | Upload `sample-data/3-broken-file.json` | Explains that it is not valid JSON and shows the parser message |
| JSON that is not Wazuh alerts | Upload `sample-data/5-not-wazuh-alerts.json` | Explains which fields an alert needs |
| Partly damaged export | Upload `sample-data/2-partly-damaged-alerts.json` | Loads the 12 good alerts and reports that 3 records were skipped |
| File too large or too many alerts | Any file over 2 MB or 2,000 alerts | Refuses and asks for a shorter time range |
| No reviewer name | Leave the name empty and try to approve | The dialog asks for a name and will not record without one |
| Evidence not reviewed | Approve without ticking the box | The dialog will not record the approval |
| Permission denied | Settings, set role to Viewer, try to decide | The decision is refused with an explanation |
| Enrichment unavailable | Settings, simulate a reputation feed outage | Verdicts are recomputed without reputation data and confidence is lowered |
| Empty queue | Decide every case, or filter to nothing | An empty state says what happened and what to do next |
| Unknown case address | Open `#/case/AF-000000` | A message explains that the case is not in the loaded alerts |
| Storage full or blocked | Private window with storage disabled | A warning says data will not survive closing the page; the tab keeps working |
| Damaged saved data | Corrupt the `aegisflow.v1` value in local storage | Data is reset safely and the user is told |

## User-testing protocol (the exam requires at least five relevant users)

Use the same script for every participant so results can be compared.

1. **Consent.** Explain that this is a course project, that no personal data is collected, that they are identified only as P01 to P05, and that they can stop at any time. Record that they agreed.
2. **Profile.** Note the relevant background only, for example "final-year cybersecurity student, has used Wazuh in labs" or "system administrator, 3 years".
3. **Manual baseline (optional but valuable).** Give them the raw file `sample-data/1-valid-alerts.json` and ask: "Is anything here worth acting on?" Time it.
4. **Tasks in AegisFlow**, without help:
   - T1. Load the lab dataset and find the most serious case.
   - T2. Explain in your own words what happened in that case and why AegisFlow thinks so.
   - T3. Record a decision for it.
   - T4. Find a case you would dismiss, and dismiss it.
   - T5. Switch the interface to the other language and decide one more case.
   - T6. Upload `sample-data/3-broken-file.json` and say what the message means.
5. **Record** for each task: completed or not, what the participant did, where they hesitated, what they said. Ask them to fill in the feedback form on each decided case.
6. **Export.** Open **Session report** and press **Export CSV** before the next participant. The file contains time to decision, the decision, whether it matched the recommendation, the rating and the trust score. Then use **Settings, Clear all data**.
7. **After five sessions,** list the problems by how many participants met them, fix at least three, and retest the fixed points. Write the before and after into Template E of the evidence portfolio.

Do not invent participants, quotations or timings. If fewer than five sessions were run, report the real number.

## Technical overview

| Aspect | Description |
|---|---|
| Platform | Static single-page web application. HTML, CSS and JavaScript, with no framework and no build step. Runs in any current browser, on desktop and phone. |
| Architecture | Six scripts loaded in order: `i18n.js` (English and Kazakh text), `intel.js` (address classification and the bundled reputation lists), `engine.js` (parsing, correlation, scoring, recommendation, SHA-256), `demo-data.js` (the lab dataset), `store.js` (browser storage) and `app.js` (pages and dialogs). The engine has no access to the page or the network and is covered by automated tests. |
| How a verdict is reached | Alerts are grouped by source address and host (60-minute gap for address-based cases, 15-minute gap for host-only sessions). Each group is compared with nine known patterns. Points are added or removed for rule level, volume, pattern, reputation and context. Below 25 is likely benign, 25 to 54 needs review, 55 and above is likely malicious. Host activity that starts within an hour of a successful password-guessing attack on the same host is linked to it. The rules are fixed and readable; this version uses no generative AI model. |
| Data storage | Browser `localStorage` under one key, `aegisflow.v1`: reviewer name and role, language, imported alerts, decisions, audit log, feedback and timers. Nothing is stored on a server. |
| Integrations | Input: Wazuh alert JSON, in the `alerts.json` line format, as a JSON array, or as an indexer or API export. Output: an action ticket as text and CSV exports of the audit log and session report. There is no live connection to Wazuh, a firewall, or a ticketing system in this version. |
| Dependencies | None at run time. Node.js 18 or later is needed only to run the tests and regenerate sample files. No third-party libraries, fonts or CDNs. |
| Deployment | Copy the folder to any static host. No environment variables, keys or database. |
| Important limitations | Rule-based analysis covers nine patterns and will label anything else "no known pattern". The reputation data is a small demo list. Decisions are recorded and not executed. The audit log lives in one browser and can be cleared by the user. The reviewer name is typed, not authenticated. Limits: 2,000 alerts or 2 MB per import. |

## Privacy, security, accessibility and safe failure

**Privacy.** Alerts are analysed in the browser and never leave it. The page sends no requests after it has loaded. The lab dataset is synthetic: hosts and users are invented, and public-looking addresses come from the documentation ranges reserved by RFC 5737.

**Security.**
- A Content Security Policy in `index.html` allows scripts and styles only from the site's own folder and blocks every outgoing connection.
- Alert text is treated as hostile, because attackers can influence what is written to logs. It reaches the page only as text, never as HTML.
- A source address is accepted only if it consists of address characters, so a crafted log line cannot inject anything into the example firewall command.
- CSV exports neutralise cells that start with `=`, `+`, `-` or `@`, so a spreadsheet cannot run them as formulas.
- There are no API keys or secrets in the code.

**Accessibility.** Semantic headings, tables and form labels; full keyboard operation with a visible focus ring; a skip link; dialogs that trap focus and return it; errors announced to screen readers; colour is never the only signal (severity and verdict are always written out); text contrast of at least 4.5 to 1; layouts that reflow down to phone width; motion reduced when the system asks for it; the page language attribute switches with the interface language.

**Safe failure.** Bad input never replaces good data. When reputation data is missing the app says so and lowers its confidence instead of guessing. Unknown situations are sent to a person. Nothing is executed automatically.

## Tests

```bash
node --test tests/
```

21 checks cover the lab dataset (211 alerts become 11 cases with the expected verdicts), import of valid, damaged, empty and unrelated files, the alert limit, behaviour during a reputation outage, hostile field values, the SHA-256 implementation against the platform one, and that English and Kazakh contain the same text keys and placeholders.

To regenerate the sample files:

```bash
node tools/make-sample-data.js
```

## What changed from the Assignment 5 plan, and why

| Planned in Assignment 5 | Built | Evidence or constraint behind the change |
|---|---|---|
| Summaries written by a cloud language model, with redaction | Fixed, readable rules that run in the browser; no generative model | Privacy concern raised in customer development (R8), the risk of invented facts (weakness W1, R7), and the need for a demonstration that behaves the same every time |
| Live read-only Wazuh API connector with an API key | Import of the `alerts.json` export by file or paste | A browser cannot call a Wazuh manager directly (cross-origin rules, self-signed certificates), and asking testers for API keys conflicts with buyer risk aversion (threat T2) |
| English interface | English and Kazakh interface, including generated summaries and error messages | Exam requirement, and bilingual documentation was already named as a service differentiator in Assignment 4 |
| Confidence shown as a three-level flag | Three-level flag plus the reasons for it and a visible risk score built from listed factors | R2 and R7 asked to see why the tool reached a conclusion |
| Not planned | Host changes are linked to a preceding successful attack on the same host | Technical finding while building the dataset: the account and sudoers changes looked routine when read alone |
| Not planned | Session report with time to decision and CSV export | Needed to measure the Assignment 5 hypothesis (triage time, usefulness, trust) during user testing |

Changes that come from testing with real users must be added to this table after the sessions are run.

## Before you submit

- [ ] Put the folder online and test the public link on a second device or browser.
- [ ] Have a fluent Kazakh speaker read the Kazakh interface (`js/i18n.js`, the `kk` block) and correct wording and terminology. The first draft was produced with AI assistance.
- [ ] Run five user-testing sessions and export the CSV after each one.
- [ ] Record the backup screen recording of the core journey in both languages.
- [ ] Declare AI assistance for this code in Template L of the evidence portfolio. Each team member should be able to explain how a verdict is computed (`js/engine.js`) and how the interface text is switched (`js/i18n.js`).

## Folder map

```
index.html              page shell and security policy
css/styles.css          all styles
js/i18n.js              English and Kazakh text
js/intel.js             address classification and demo reputation lists
js/engine.js            parsing, correlation, scoring, recommendation, SHA-256
js/demo-data.js         synthetic Wazuh lab dataset (211 alerts)
js/store.js             browser storage with failure handling
js/app.js               pages, dialogs, exports
sample-data/            files for the import demonstration and its error cases
tests/engine.test.js    automated checks
tools/make-sample-data.js
```
