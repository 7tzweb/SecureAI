import assert from "node:assert/strict";
import {
  buildSqlResponseSignature,
  classifyParameter,
  findStrictDbErrorSignature,
  responseDiffDimensions,
} from "../src/security/probes/sqlEvidence";

const googleLikeSearch = `
  <html>
    <head><title>Google Search</title><script nonce="abc123">window._req="1700000000000"</script></head>
    <body>Search results for ' invalid query syntax. Try another search.</body>
  </html>
`;

assert.equal(findStrictDbErrorSignature(googleLikeSearch), null, "Google-like generic search text must not be a DB error");

assert.equal(classifyParameter("continue", "https://accounts.example.com/login?continue=https://app.example.com"), "redirect");
assert.equal(classifyParameter("q", "https://shop.example.com/search?q=test"), "search");

const juiceBaseline = buildSqlResponseSignature({
  status: 200,
  contentType: "application/json",
  bodyText: JSON.stringify({ data: [] }),
  url: "https://juice.example/rest/products/search?q=none",
});
const juiceExpanded = buildSqlResponseSignature({
  status: 200,
  contentType: "application/json",
  bodyText: JSON.stringify({ data: Array.from({ length: 46 }, (_, id) => ({ id, name: `item-${id}` })) }),
  url: "https://juice.example/rest/products/search?q=' OR 1=1--",
});

assert.ok(
  responseDiffDimensions(juiceBaseline, juiceExpanded).includes("record-count"),
  "Structured record expansion must remain strong SQLi evidence",
);

const mysqlError = findStrictDbErrorSignature("You have an error in your SQL syntax near '' OR 1=1-- at line 1");
assert.equal(mysqlError?.family, "mysql", "Strict MySQL signature should be detected");

const dynamicA = buildSqlResponseSignature({
  status: 200,
  contentType: "text/html",
  bodyText: `<html><head><script nonce="a1b2c3">var requestId="eyJ${"A".repeat(40)}"</script></head><body>Welcome to Search</body></html>`,
});
const dynamicB = buildSqlResponseSignature({
  status: 200,
  contentType: "text/html",
  bodyText: `<html><head><script nonce="z9y8x7">var requestId="eyJ${"B".repeat(40)}"</script></head><body>Welcome to Search</body></html>`,
});

assert.deepEqual(responseDiffDimensions(dynamicA, dynamicB), [], "Dynamic nonce/token noise should not create SQLi diff evidence");

console.log("SQL evidence regression checks passed");
