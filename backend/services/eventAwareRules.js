const EVENT_AWARE_RULES = [
  { ruleId: "TRAV_001", fields: [["http", "path"]] },
  { ruleId: "TRAV_002", fields: [["http", "path"]] },
  { ruleId: "PROM_001", fields: [["http", "path"]] },
  { ruleId: "CONF_001", fields: [["http", "path"]] },
  { ruleId: "REDIR_001", fields: [["http", "query"]] },
  {
    ruleId: "SCAN_001",
    fields: [["http", "userAgent"]],
    pattern: "(?i)(sqlmap|nikto|nmap|burp|dirbuster|gobuster|zgrab|masscan)"
  },
  { ruleId: "EXFIL_001", fields: [["process", "command"]] },
  { ruleId: "SQLI_001", fields: [["http", "body"]] },
  { ruleId: "SQLI_002", fields: [["http", "body"]] },
  { ruleId: "SQLI_003", fields: [["http", "body"], ["http", "query"]] },
  { ruleId: "SQLI_004", fields: [["http", "body"]] },
  { ruleId: "XSS_001", fields: [["http", "body"]] },
  { ruleId: "XSS_003", fields: [["http", "body"]] },
  { ruleId: "XXE_001", fields: [["http", "body"]] },
  { ruleId: "GRAPHQL_001", fields: [["http", "body"]] },
  { ruleId: "SSRF_001", fields: [["http", "body"], ["http", "url"], ["http", "query"]] }
];

module.exports = { EVENT_AWARE_RULES };
