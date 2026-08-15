/**
 * Customer security-questionnaire answerer (the wedge).
 *
 * Takes a pasted/exported questionnaire (one question per line) and drafts an
 * answer for each by mapping it to the readiness report's evidence: what the
 * scan measured plus what the owner attested. Questions it can't map are marked
 * NEEDS HUMAN INPUT rather than guessed.
 *
 * Offline and deterministic. This drafts a response grounded in evidence; it is
 * not a certification, and the owner must review every answer before sending.
 */

// Keyword -> NIS2 measure. First match wins; order specific before general.
const RULES = [
  { re: /\b(mfa|multi.?factor|two.?factor|2fa)\b/i, measure: "j" },
  { re: /\b(spf|dkim|dmarc)\b|email (auth|spoof|security)/i, measure: "j" },
  { re: /encrypt.*(at.?rest|storage|database|disk)|data.?at.?rest/i, measure: "h" },
  { re: /\b(tls|https|ssl)\b|encrypt.*(transit|transport)|in transit/i, measure: "h" },
  { re: /incident (response|handling|management|report)|breach notif|report.*breach/i, measure: "b" },
  { re: /backup|business continuity|disaster recovery|\bdr\b|resilien/i, measure: "c" },
  { re: /supplier|vendor|third.?part|supply.?chain|sub.?processor|sbom/i, measure: "d" },
  { re: /access control|least privilege|\brbac\b|authoris|authoriz|joiner|leaver|offboard|privileged access/i, measure: "i" },
  { re: /asset (inventory|management|register)|inventory of/i, measure: "i" },
  { re: /vulnerab|patch|penetration|pentest|secure (develop|coding|sdlc)|dependency|cve/i, measure: "e" },
  { re: /risk (assessment|analysis|management|register)|security polic|infosec|isms/i, measure: "a" },
  { re: /training|awareness|phishing|security education/i, measure: "g" },
  { re: /effectiveness|periodic review|internal audit|security metrics|kpi/i, measure: "f" },
  { re: /secret|hardcoded credential|key management|api key/i, measure: "d" },
];

const STATUS_ANSWER = {
  met: "Yes",
  partial: "Partial",
  gap: "In progress",
  "n/a": "N/A",
};

/** Parse a questionnaire file: one question per line; blanks and # comments skipped. */
export function parseQuestionnaire(text) {
  return String(text || "").split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    // strip a leading numbering/bullet ("1. ", "- ", "* ", "Q3: ")
    .map((l) => l.replace(/^(\d+[.)]\s*|[-*]\s*|q\d+[:.]\s*)/i, "").trim())
    .filter(Boolean);
}

/**
 * Answer a questionnaire from a readiness report.
 * @param {string[]} questions
 * @param {object} readiness - from buildReadiness()
 */
export function answerQuestionnaire(questions, readiness) {
  const byId = new Map((readiness?.measures || []).map((m) => [m.id, m]));

  const answers = questions.map((question) => {
    const rule = RULES.find((r) => r.re.test(question));
    if (!rule) {
      return { question, measure: null, answer: "NEEDS HUMAN INPUT", evidence: [] };
    }
    const m = byId.get(rule.measure);
    if (!m) {
      return { question, measure: rule.measure, answer: "NEEDS HUMAN INPUT", evidence: [] };
    }
    const evidence = (m.evidence || []).map((e) =>
      e.source === "scan" ? `scan:${e.method}` : `attested:${e.answer}`,
    );
    return {
      question,
      measure: rule.measure,
      measureTitle: m.title,
      status: m.status,
      answer: STATUS_ANSWER[m.status] || "NEEDS HUMAN INPUT",
      evidence,
    };
  });

  const summary = { answered: 0, needsHuman: 0 };
  for (const a of answers) {
    if (a.answer === "NEEDS HUMAN INPUT") summary.needsHuman++;
    else summary.answered++;
  }
  return { total: answers.length, summary, answers };
}

/** Render the answered questionnaire as Markdown. */
export function formatQuestionnaireMarkdown(result) {
  if (!result) return "";
  const L = [];
  L.push("# Security questionnaire, draft response");
  L.push("");
  L.push("> Draft answers mapped from a Penthera scan and self-assessment. **Review every answer before sending.** Items marked NEEDS HUMAN INPUT could not be mapped and must be answered by a person. This is a drafting aid, not a certification.");
  L.push("");
  L.push(`**${result.total}** questions: ${result.summary.answered} drafted, ${result.summary.needsHuman} need human input.`);
  L.push("");
  L.push("| Question | Draft answer | Basis (Art. 21 / evidence) |");
  L.push("|----------|--------------|----------------------------|");
  for (const a of result.answers) {
    const basis = a.measure
      ? `(${a.measure}) ${a.status || "?"}${a.evidence?.length ? `: ${a.evidence.slice(0, 3).join(", ")}` : ""}`
      : "unmapped";
    L.push(`| ${a.question.replace(/\|/g, "\\|")} | ${a.answer} | ${basis.replace(/\|/g, "\\|")} |`);
  }
  L.push("");
  const gaps = result.answers.filter((a) => a.answer === "NEEDS HUMAN INPUT").map((a) => a.question);
  if (gaps.length) {
    L.push("## Needs human input");
    L.push("");
    gaps.forEach((q) => L.push(`- ${q}`));
    L.push("");
  }
  return L.join("\n");
}
