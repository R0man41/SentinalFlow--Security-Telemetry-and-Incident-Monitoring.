const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

describe("frontend timeline rendering", () => {
  it("renders timeline values as text rather than executable HTML", () => {
    const source = fs.readFileSync(path.join(__dirname, "../frontend/app.js"), "utf8");
    const timelineBody = { innerHTML: "" };
    const context = {
      document: {
        addEventListener() {},
        getElementById(id) {
          assert.equal(id, "timeline-body");
          return timelineBody;
        }
      },
      Date
    };
    vm.runInNewContext(source, context);

    context.renderTimelineEntries([{
      timestamp: "2026-09-29T10:00:00.000Z",
      action: '<img src=x onerror="run()">',
      from: "<svg onload=run()>",
      to: "<script>run()</script>",
      by: "<b>operator</b>"
    }]);

    assert.doesNotMatch(timelineBody.innerHTML, /<img|<svg|<script|<b>/i);
    assert.match(timelineBody.innerHTML, /&lt;img/);
    assert.match(timelineBody.innerHTML, /&lt;svg/);
    assert.match(timelineBody.innerHTML, /&lt;script&gt;/);
    assert.match(timelineBody.innerHTML, /&lt;b&gt;operator&lt;\/b&gt;/);
  });
});
