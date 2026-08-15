/**
 * Local self-assessment for the organisational half of NIS2 Article 21, the
 * measures a scanner cannot test and must capture as an honest attestation.
 *
 * Runs entirely offline. The question bank is data; answers are recorded to a
 * JSON file that the readiness report consumes. Every answer becomes an evidence
 * record with provenance (source: self-assessment / attestation).
 *
 * Proportionality is the governing principle: for a small entity, a two-page
 * policy that genuinely exists counts. The questions ask whether something
 * exists and is used, not whether it is enterprise-grade.
 */

// One or more attestation questions per Article 21(2) measure. `id` is stable
// (used as the answer key and in provenance). Answers: yes | partial | no | na.
export const QUESTIONS = [
  { id: "a1", measure: "a", text: "Do you have a written information-security policy (even one to two pages)?", guidance: "A short, real policy that staff can find counts. It doesn't need to be long." },
  { id: "a2", measure: "a", text: "Have you done a basic risk assessment of your most important systems and data?", guidance: "Identify what would hurt most if lost/breached, and the top risks to it." },
  { id: "b1", measure: "b", text: "Do you have a documented incident-response process (who does what, who to call)?", guidance: "Even a one-page runbook with roles and contacts." },
  { id: "b2", measure: "b", text: "Do you know your NIS2 reporting deadlines (24h / 72h / 1 month) and who you would notify?", guidance: "See the incident-report helper; the authority is your CSIRT / RDI." },
  { id: "c1", measure: "c", text: "Do you take regular backups of important data and systems?", guidance: "Automated, off-site or immutable backups are best." },
  { id: "c2", measure: "c", text: "Have you successfully restored from a backup in the last 12 months?", guidance: "An untested backup is not a backup. A single real restore test counts." },
  { id: "d1", measure: "d", text: "Do you keep a list of your key suppliers/vendors (especially those with access to your data or systems)?", guidance: "A simple inventory is enough to start." },
  { id: "d2", measure: "d", text: "Do you assess your suppliers' security (questionnaire, certification, or contractual clauses)?", guidance: "Penthera's passive supplier rating can help for the technical part." },
  { id: "e1", measure: "e", text: "Do you have a process for applying security updates and handling reported vulnerabilities?", guidance: "Patching cadence + a way for people to report issues (e.g. a SECURITY.md)." },
  { id: "f1", measure: "f", text: "Do you periodically review whether your security measures are actually working (re-scan, review incidents)?", guidance: "Penthera baseline diffs and re-scans provide this evidence." },
  { id: "g1", measure: "g", text: "Do staff receive basic security-awareness guidance (phishing, passwords, reporting)?", guidance: "A short onboarding briefing and occasional reminders count." },
  { id: "h1", measure: "h", text: "Is sensitive data encrypted at rest (databases, backups, laptops)?", guidance: "Penthera checks encryption in transit (TLS); at-rest is your attestation." },
  { id: "i1", measure: "i", text: "Do you have an access-control approach (least privilege, and removing access when people leave)?", guidance: "A joiner/leaver checklist and role-based access are proportionate for most SMEs." },
  { id: "i2", measure: "i", text: "Do you keep an inventory of your assets (devices, systems, key data)?", guidance: "A spreadsheet is a fine starting point." },
  { id: "j1", measure: "j", text: "Is multi-factor authentication (MFA) enforced for admin/privileged accounts and email?", guidance: "MFA on email and admin panels is the single highest-value control here." },
];

const VALID_ANSWERS = new Set(["yes", "partial", "no", "na"]);

/** A blank assessment template the user or agent fills in. */
export function blankAssessment() {
  const answers = {};
  for (const q of QUESTIONS) {
    answers[q.id] = { answer: "", note: "" };
  }
  return {
    _about: "Penthera NIS2 self-assessment. Answer each: yes | partial | no | na, with an optional note. Offline; no data leaves your machine. See lib/compliance/self-assessment.js for the questions.",
    framework: "nis2",
    answers,
  };
}

/** Normalise a loaded answers object; ignores unknown ids and invalid values. */
export function normalizeAnswers(loaded) {
  const raw = loaded?.answers || loaded || {};
  const out = {};
  for (const q of QUESTIONS) {
    const a = raw[q.id];
    const answer = typeof a === "string" ? a : a?.answer;
    if (answer && VALID_ANSWERS.has(String(answer).toLowerCase())) {
      out[q.id] = { answer: String(answer).toLowerCase(), note: (a && a.note) || "" };
    }
  }
  return out;
}

/** Questions for a given measure id (a-j). */
export function questionsForMeasure(measure) {
  return QUESTIONS.filter((q) => q.measure === measure);
}
