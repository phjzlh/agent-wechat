// Explicit-connect launcher checks against a local HTTP fixture, never WeChat.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFileSync, spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { loadPreviewSecret, readPrivateText, requirePrivateDirectory } from "../packages/client-ui/scripts/private-preview-path.mjs";
import { makePrivateTestDirectory } from "../packages/client-ui/test/support/private-directory.mjs";

const data = await mkdtemp(join(tmpdir(), "agentwechat-connect-test-"));
const token = "synthetic-browser-token";
const paths = [];
let child;
const backend = createServer((req, res) => {
  paths.push(req.url);
  res.setHeader("Content-Type", "application/json");
  if (req.headers.authorization !== `Bearer ${token}`) {
    res.statusCode = 401;
    return res.end("{}");
  }
  if (req.url === "/v1/status")
    return res.end(JSON.stringify({ version: { backend: "native" } }));
  if (req.url === "/v1/accounts")
    return res.end(JSON.stringify({ items: [{ id: "test-account" }] }));
  return res.end(JSON.stringify({ ok: true }));
});
try {
  await new Promise((done) => backend.listen(0, "127.0.0.1", done));
  if (process.platform === "win32") {
    makePrivateTestDirectory(data);
    const loose = join(data, "loose");
    await writeFile(loose, token);
    execFileSync("icacls.exe", [loose, "/grant", "*S-1-1-0:R"]);
    await assert.rejects(
      readPrivateText(loose, "Use an owner-only connection file"),
      /owner-only connection file/,
    );
    await assert.rejects(loadPreviewSecret(loose, "Private secret required"), /Private secret required/);
    assert.equal(await readFile(loose, "utf8"), token, "an existing file must never be overwritten");

    // A private directory can grant rights that do not inherit to new files.
    const noInheritance = join(data, "no-inherited-file-rights");
    await mkdir(noInheritance);
    makePrivateTestDirectory(noInheritance, { inherit: false });
    await requirePrivateDirectory(noInheritance, "Private directory required");
    const generated = join(noInheritance, "secret");
    const value = await loadPreviewSecret(generated, "Private secret required");
    assert.match(value, /^[0-9a-f]{64}$/);
    assert.equal(await readPrivateText(generated, "Private secret required"), value);
    assert.equal(await loadPreviewSecret(generated, "Private secret required"), value);
  }
  const tokenFile = join(data, "token");
  await writeFile(tokenFile, token, { mode: 0o600 });
  const reservation = createServer();
  await new Promise((done) => reservation.listen(0, "127.0.0.1", done));
  const port = reservation.address().port;
  await new Promise((done) => reservation.close(done));
  child = spawn(
    process.execPath,
    [
      resolve("packages/client-ui/scripts/connect.mjs"),
      "--server",
      `http://127.0.0.1:${backend.address().port}`,
      "--account",
      "test-account",
      "--token-file",
      tokenFile,
      "--state-dir",
      data,
    ],
    {
      env: {
        ...process.env,
        CLIENT_UI_PORT: String(port),
        CLIENT_UI_ORIGIN: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "",
    diagnostics = "";
  child.stderr.on(
    "data",
    (part) => (diagnostics = (diagnostics + part).slice(-2000)),
  );
  const ready = await new Promise((done, reject) => {
    const timeout = setTimeout(
      () => reject(Error(`Launcher startup timed out: ${diagnostics}`)),
      15000,
    );
    child.once("exit", () => {
      clearTimeout(timeout);
      reject(Error(`Launcher exited: ${diagnostics}`));
    });
    child.stdout.on("data", (part) => {
      output += part;
      const match = output.match(
        /(http:\/\/127\.0\.0\.1:\d+)\/#dev=([a-f0-9]{64})/,
      );
      if (match) {
        clearTimeout(timeout);
        done({ origin: match[1], key: match[2] });
      }
    });
  });
  const headers = { Authorization: `Bearer ${ready.key}` };
  const session = ready.origin + "/__dev/session";
  assert.equal((await fetch(session)).status, 403);
  assert.equal(
    (
      await fetch(session, {
        headers: { ...headers, Origin: "https://untrusted.example" },
      })
    ).status,
    403,
  );
  const response = await fetch(session, { headers });
  assert.equal(response.status, 200);
  assert.match(response.headers.get("set-cookie"), /HttpOnly; SameSite=Strict/);
  assert.match(response.headers.get("set-cookie"), /Max-Age=2592000/);
  const cookie = response.headers.get("set-cookie").split(";")[0];
  assert.equal(
    (await fetch(session, { headers: { Cookie: cookie } })).status,
    200,
  );
  const config = await response.json();
  assert.equal(config.simulator, false);
  assert.equal(config.endpoint, ready.origin);
  assert.equal(config.token, ready.key);
  assert.notEqual(config.token, token, "the daemon key stays server-side");
  for (const [path, method] of [
    ["/v1/accounts", "POST"],
    ["/v1/accounts/other/auth/login", "POST"],
    ["/v1/accounts/other/auth/logout", "POST"],
    ["/v1/accounts/other", "DELETE"],
  ]) {
    assert.equal(
      (await fetch(ready.origin + path, { method, headers })).status,
      200,
    );
  }
  const beforeRejected = paths.length;
  assert.equal(
    (
      await fetch(ready.origin + "/v1/accounts", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      })
    ).status,
    401,
  );
  assert.equal(
    (
      await fetch(ready.origin + "/v1/accounts", {
        method: "POST",
        headers: { ...headers, Origin: "https://untrusted.example" },
      })
    ).status,
    401,
  );
  assert.equal(paths.length, beforeRejected);
  assert.equal(
    (await fetch(ready.origin + "/__dev/control", { method: "POST", headers }))
      .status,
    404,
  );
  assert.equal(
    (
      await fetch(ready.origin + "/v1/accounts/other/threads", {
        headers,
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await fetch(ready.origin + "/v1/tokens", {
        method: "POST",
        headers,
      })
    ).status,
    403,
  );
  assert.equal(
    (await fetch(ready.origin + "/v1/accounts/test-account/threads")).status,
    401,
  );
  assert.equal(
    (
      await fetch(ready.origin + "/v1/accounts/test-account/threads", {
        headers,
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await fetch(ready.origin + "/v1/daemon/shutdown", {
        method: "POST",
        headers,
      })
    ).status,
    403,
  );
  assert.ok(!paths.includes("/v1/daemon/shutdown"));
  child.kill("SIGTERM");
  await new Promise((done) => child.once("exit", done));
  assert.equal(
    (
      await fetch(`http://127.0.0.1:${backend.address().port}/v1/status`, {
        headers: { Authorization: `Bearer ${token}` },
      })
    ).status,
    200,
  );
  console.log(
    JSON.stringify({
      ok: true,
      checks: [
        "explicit native target",
        "private bootstrap and origin checks",
        "no simulator controls",
        "profile management with server-side daemon key",
        "owner routes denied",
        "bearer required",
        "leaves daemon running",
      ],
    }),
  );
} finally {
  if (child?.exitCode === null && child.signalCode === null)
    child.kill("SIGTERM");
  backend.closeAllConnections();
  await new Promise((done) => backend.close(done));
  await rm(data, { recursive: true, force: true });
}
