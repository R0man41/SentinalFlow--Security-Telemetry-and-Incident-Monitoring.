const express = require("express");
const externalEventNormalizer = require("../services/externalEventNormalizer");
const securityAnalysisService = require("../services/securityAnalysisService");
const { recentEventStore } = require("../services/recentEventStore");
const { stripInternalEvidence } = require("../services/eventAwareMatcher");
const { asyncHandler } = require("../utils/httpError");

const router = express.Router();

router.post("/", asyncHandler(async (req, res) => {
  const batch = externalEventNormalizer.createEventBatch(req.body);
  const event = batch.events[0];
  let hasExternalIdentity = false;
  let identityContext = null;

  if (event.externalEventId !== undefined) {
    hasExternalIdentity = true;
    const fingerprint = externalEventNormalizer.fingerprintExternalEvent(event);
    const identity = recentEventStore.registerProcessing({
      sourceService: event.source.service,
      externalEventId: event.externalEventId,
      eventId: event.eventId,
      fingerprint
    });

    if (identity.status === "conflict") {
      return res.status(409).json({ error: "event_identity_conflict" });
    }
    if (identity.status === "processing") {
      return res.status(202).json({
        accepted: true,
        processing: true,
        eventId: identity.eventId
      });
    }
    if (identity.status === "completed") {
      return res.status(200).json({
        accepted: true,
        duplicate: true,
        eventId: identity.eventId
      });
    }

    if (identity.status === "retry") event.eventId = identity.eventId;
    identityContext = {
      sourceService: event.source.service,
      externalEventId: event.externalEventId,
      eventId: identity.eventId,
      fingerprint
    };
  }

  let response;
  try {
    const { detection, incident } = await securityAnalysisService.analyzeBatch(batch, {
      useRecentEventState: true,
      buildIncidentDescription: ({ detection: result, matchedSummary }) =>
        `Threat detected from an ingested security event. Type: ${result.type}. Severity: ${result.severity}. Matched rules: ${matchedSummary}.`
    });
    response = {
      accepted: true,
      eventId: event.eventId,
      detection: stripInternalEvidence(detection),
      incident
    };
  } catch (error) {
    if (identityContext) {
      recentEventStore.markFailed(identityContext);
      recentEventStore.removeEvent(identityContext.eventId);
    }
    throw error;
  }

  if (hasExternalIdentity) {
    // Complete the identity before sending the response. A lost response can
    // then be retried without rerunning detection or incident persistence.
    recentEventStore.markCompleted(identityContext);
    response.duplicate = false;
  }
  res.status(201).json(response);
}));

module.exports = router;
