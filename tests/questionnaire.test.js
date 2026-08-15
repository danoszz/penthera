/**
 * Customer-questionnaire answerer: parse, keyword->measure mapping, honest
 * NEEDS HUMAN INPUT for anything unmapped.
 */
import { describe, it, expect } from "vitest";
import { parseQuestionnaire, answerQuestionnaire, formatQuestionnaireMarkdown } from "../lib/compliance/questionnaire.js";

const readiness = {
  measures: [
    { id: "h", title: "Cryptography", status: "met", evidence: [{ source: "scan", method: "probe:tls" }] },
    { id: "j", title: "MFA & secure comms", status: "gap", evidence: [] },
    { id: "e", title: "Vulnerability handling", status: "partial", evidence: [{ source: "scan", method: "probe:openapi" }] },
    { id: "d", title: "Supply chain", status: "met", evidence: [{ source: "self-assessment", answer: "yes" }] },
  ],
};

describe("parseQuestionnaire", () => {
  it("strips numbering/bullets, skips blanks and comments", () => {
    const qs = parseQuestionnaire("1. Do you enforce MFA?\n- Is traffic TLS?\n# a note\n\nQ3: Do you run scans?");
    expect(qs).toEqual(["Do you enforce MFA?", "Is traffic TLS?", "Do you run scans?"]);
  });
});

describe("answerQuestionnaire", () => {
  it("maps keywords to measures and derives the answer from readiness status", () => {
    const r = answerQuestionnaire(
      ["Is all traffic encrypted with TLS?", "Do you enforce MFA?", "Do you run vulnerability scans?", "Do you assess your suppliers?"],
      readiness,
    );
    const byQ = Object.fromEntries(r.answers.map((a) => [a.question, a.answer]));
    expect(byQ["Is all traffic encrypted with TLS?"]).toBe("Yes");        // h met
    expect(byQ["Do you enforce MFA?"]).toBe("In progress");               // j gap
    expect(byQ["Do you run vulnerability scans?"]).toBe("Partial");       // e partial
    expect(byQ["Do you assess your suppliers?"]).toBe("Yes");             // d met
  });

  it("marks unmapped questions NEEDS HUMAN INPUT (never guesses)", () => {
    const r = answerQuestionnaire(["What is your company's favourite colour?"], readiness);
    expect(r.answers[0].answer).toBe("NEEDS HUMAN INPUT");
    expect(r.summary.needsHuman).toBe(1);
  });

  it("cites evidence for mapped answers", () => {
    const r = answerQuestionnaire(["Do you use TLS?"], readiness);
    expect(r.answers[0].evidence).toContain("scan:probe:tls");
  });
});

describe("formatQuestionnaireMarkdown", () => {
  it("renders a table, a needs-human list, and the review disclaimer", () => {
    const md = formatQuestionnaireMarkdown(
      answerQuestionnaire(["Do you enforce MFA?", "Favourite colour?"], readiness),
    );
    expect(md).toMatch(/review every answer before sending/i);
    expect(md).toContain("Draft answer");
    expect(md).toContain("Needs human input");
  });
});
