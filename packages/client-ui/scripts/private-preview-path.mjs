import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const maxFileSize = 32768;

// Windows mode bits are synthetic. Create secrets with an explicit DACL and
// check the owner and DACL on the same handle used to read a file.
const accessPrivate = Buffer.from(`
  $ErrorActionPreference = 'Stop'
  $path = $env:AGENT_WECHAT_PREVIEW_ACL_PATH
  $mode = $env:AGENT_WECHAT_PREVIEW_ACL_MODE
  $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')

  function AssertPrivate($acl) {
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
      $acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($descriptor.Owner.Value -ne $userSid.Value -or $null -eq $descriptor.DiscretionaryAcl) {
      exit 1
    }
    foreach ($ace in $descriptor.DiscretionaryAcl) {
      if ($ace.AceType -eq 'AccessDenied') { continue }
      if ($ace.AceType -ne 'AccessAllowed') { exit 1 }
      if ($ace.AccessMask -ne 0 -and $ace.SecurityIdentifier.Value -notin @($userSid.Value, $systemSid.Value)) {
        exit 1
      }
    }
  }

  if ($mode -eq 'secret') {
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetOwner($userSid)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($owner in @($userSid, $systemSid)) {
      $rule = [Security.AccessControl.FileSystemAccessRule]::new($owner, 'FullControl', 'Allow')
      $security.AddAccessRule($rule)
    }
    $created = $null
    try {
      $created = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew,
        [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None,
        4096, [IO.FileOptions]::None, $security)
    } catch {
      $code = $_.Exception.GetBaseException().HResult -band 0xffff
      if ($code -notin @(80, 183)) { throw }
    }
    if ($null -ne $created) {
      try {
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
          $random = New-Object byte[] 32
          $rng.GetBytes($random)
        } finally { $rng.Dispose() }
        $secret = [BitConverter]::ToString($random).Replace('-', '').ToLowerInvariant()
        $bytes = [Text.Encoding]::ASCII.GetBytes($secret)
        $created.Write($bytes, 0, $bytes.Length)
      } finally { $created.Dispose() }
    }
  }

  $attributes = [IO.File]::GetAttributes($path)
  if ($attributes -band [IO.FileAttributes]::ReparsePoint) { exit 1 }
  if ($mode -eq 'directory') {
    if (-not ($attributes -band [IO.FileAttributes]::Directory)) { exit 1 }
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
      [Security.AccessControl.AccessControlSections]::Access
    AssertPrivate ([IO.Directory]::GetAccessControl($path, $sections))
    exit 0
  }
  $file = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    if ($file.Length -gt ${maxFileSize}) { exit 1 }
    AssertPrivate ($file.GetAccessControl())
    $reader = [IO.StreamReader]::new($file, [Text.UTF8Encoding]::new($false, $true), $true)
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    [Console]::Write($reader.ReadToEnd())
  } finally { $file.Dispose() }
`, "utf16le").toString("base64");

async function windowsAccess(path, mode, message) {
  try {
    const { stdout } = await run(
      join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", accessPrivate],
      {
        env: { ...process.env, AGENT_WECHAT_PREVIEW_ACL_PATH: path, AGENT_WECHAT_PREVIEW_ACL_MODE: mode },
        windowsHide: true,
        timeout: 5000,
      },
    );
    return stdout;
  } catch {
    throw new Error(message);
  }
}

export async function requirePrivateDirectory(path, message) {
  if (!(await lstat(path)).isDirectory())
    throw new Error(message);
  if (process.platform === "win32") await windowsAccess(path, "directory", message);
}

export async function readPrivateText(path, message) {
  if (process.platform === "win32") return windowsAccess(path, "read", message);
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = await file.stat();
    if (!info.isFile() || info.mode & 0o077 || info.size > maxFileSize)
      throw new Error(message);
    return await file.readFile("utf8");
  } catch {
    throw new Error(message);
  } finally {
    await file?.close();
  }
}

export async function loadPreviewSecret(path, message) {
  if (process.platform === "win32") return windowsAccess(path, "secret", message);
  try {
    await writeFile(path, randomBytes(32).toString("hex"), { mode: 0o600, flag: "wx" });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  return readPrivateText(path, message);
}
