import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

export function makePrivateTestDirectory(path, { inherit = true } = {}) {
  if (process.platform !== "win32") return;
  const identity = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" });
  const userSid = identity.match(/S-1-[\d-]+/)?.[0];
  assert.ok(userSid, "the fixture needs the current Windows user SID");
  const rights = inherit ? "(OI)(CI)F" : "F";
  execFileSync("icacls.exe", [path, "/inheritance:r", "/grant:r", `*${userSid}:${rights}`, `*S-1-5-18:${rights}`]);
}
