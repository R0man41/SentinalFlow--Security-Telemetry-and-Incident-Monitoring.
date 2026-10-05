const logAnalysisService = require("./logAnalysisService");
const {
  matchEventAwareRules,
  mergeEventAwareMatches
} = require("./eventAwareMatcher");

async function detectRawRules(context) {
  return {
    detection: await logAnalysisService.analyzeLogs(context.rawInput)
  };
}

function detectEventAwareRules(context) {
  const eventMatches = matchEventAwareRules(context.events);
  return {
    detection: mergeEventAwareMatches(context.detection, eventMatches)
  };
}

module.exports = {
  detectRawRules,
  detectEventAwareRules
};
