import assert from "node:assert/strict";
import { test } from "node:test";

import worker from "../src/index.js";

async function redirect(url) {
  const response = await worker.fetch(new Request(url));
  return { status: response.status, location: response.headers.get("Location") };
}

test("keeps the path and query on the canonical origin", async () => {
  assert.deepEqual(
    await redirect("https://pop.argus-systems.ai/advisory/BYTERAY-2026-0220.html?ref=cve"),
    { status: 301, location: "https://pop.byteray.co.uk/advisory/BYTERAY-2026-0220.html?ref=cve" },
  );
  assert.deepEqual(await redirect("https://pop.argus-systems.ai/feeds/all.atom.xml"), {
    status: 301,
    location: "https://pop.byteray.co.uk/feeds/all.atom.xml",
  });
});

test("upgrades http and drops alternate ports", async () => {
  assert.deepEqual(await redirect("http://pop.argus-systems.ai:8080/"), {
    status: 301,
    location: "https://pop.byteray.co.uk/",
  });
});

test("never redirects to another host", async () => {
  const { location } = await redirect("https://pop.argus-systems.ai//evil.example/x");
  assert.equal(new URL(location).host, "pop.byteray.co.uk");
});
