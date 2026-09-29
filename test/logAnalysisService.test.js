const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { countPatternMatches, findFirstPatternMatch } = require("../backend/services/logAnalysisService");

describe("log analysis regex safety", () => {
  it("handles an invalid regex without throwing or reporting a match", () => {
    const warnings = [];
    const originalWarn = console.warn;
    console.warn = (...args) => warnings.push(args);
    try {
      const rule = { id: "INVALID_TEST_RULE", pattern: "(", regex: true };
      assert.equal(countPatternMatches("ordinary log text", rule), 0);
      assert.equal(findFirstPatternMatch("ordinary log text", rule), null);
    } finally {
      console.warn = originalWarn;
    }
    assert.equal(warnings.length, 2);
    assert.ok(warnings.every(([message]) => message.includes("Invalid detection rule regex INVALID_TEST_RULE")));
  });
});
