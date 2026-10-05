const TEST_ADMIN_USERNAME = "test-admin";
const TEST_ADMIN_PASSWORD = "test-only-password";
const TEST_EVENT_INGESTION_TOKEN = "test-only-ingestion-token";

function configureTestCredentials() {
  process.env.ADMIN_AUTH_USERNAME = TEST_ADMIN_USERNAME;
  process.env.ADMIN_AUTH_PASSWORD = TEST_ADMIN_PASSWORD;
  process.env.EVENT_INGESTION_TOKEN = TEST_EVENT_INGESTION_TOKEN;
}

function testAdminAuthorization() {
  return "Basic " + Buffer.from(TEST_ADMIN_USERNAME + ":" + TEST_ADMIN_PASSWORD).toString("base64");
}

function testEventIngestionAuthorization() {
  return "Bearer " + TEST_EVENT_INGESTION_TOKEN;
}

module.exports = {
  configureTestCredentials,
  testAdminAuthorization,
  testEventIngestionAuthorization
};
