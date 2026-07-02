# Copyright © 2026 Saleem Abdulrasool <compnerd@compnerd.org>
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
  Assemble a self-extracting offline installer from the SFX stub and a
  built bundle layout.

.DESCRIPTION
  Appends a flat payload (installer.exe plus every external .msi/.cab in the
  bundle output directory) and a table of contents to the SFX stub, producing
  a single self-extracting .exe. The payload files are already high-compressed
  cabinets, so they are stored verbatim (no recompression). See sfx.cc for the
  on-disk format this writes.

  Run AFTER building the bundle with an external-payload flavor (offline-sfx
  or online) so installer.exe references the loose cabs rather than embedding
  them, and AFTER building sfx.vcxproj.

.EXAMPLE
  .\pack-sfx.ps1 `
    -Stub  ..\..\build\Release\amd64\sfx.exe `
    -PayloadDir ..\..\build\Release\amd64 `
    -OutFile .\swift-toolchain-offline.exe
#>
[CmdletBinding()]
param(
  # The compiled SFX stub (sfx.vcxproj output).
  [Parameter(Mandatory)] [string] $Stub,

  # Directory holding the built bundle: installer.exe + the loose *.msi/*.cab.
  [Parameter(Mandatory)] [string] $PayloadDir,

  # Destination self-extracting executable.
  [Parameter(Mandatory)] [string] $OutFile,

  # The bundle entry point the stub launches after extraction.
  [string] $LaunchTarget = "installer.exe",

  # Optional: a signtool invocation to run against $OutFile once written, e.g.
  #   -SignCommand '"C:\...\signtool.exe" sign /fd sha256 /f cert.pfx /p pw'
  # The output path is appended (quoted) as the final argument.
  [string] $SignCommand
)

$ErrorActionPreference = "Stop"

$Magic = [byte[]][char[]]"SWIFTSFX"   # 8 bytes, matches kMagic in sfx.cc.

$stubPath    = (Resolve-Path $Stub).Path
$payloadPath = (Resolve-Path $PayloadDir).Path

# Collect the launch target first, then every other .msi/.cab. Burn validates
# each payload by the hash baked into installer.exe, so these must be exactly
# the files produced alongside this installer.exe.
$launch = Join-Path $payloadPath $LaunchTarget
if (-not (Test-Path $launch)) {
  throw "Launch target '$LaunchTarget' not found in $payloadPath. Build the bundle first."
}

$files = @(Get-Item $launch)
$files += Get-ChildItem -Path $payloadPath -File |
  Where-Object { $_.Extension -in ".msi", ".cab" } |
  Sort-Object Name

Write-Host "Packing $($files.Count) payload files from $payloadPath"

# Write little-endian primitives regardless of host endianness.
function Write-UInt32([System.IO.Stream]$s, [uint32]$v) {
  $s.Write([System.BitConverter]::GetBytes($v), 0, 4)
}
function Write-UInt64([System.IO.Stream]$s, [uint64]$v) {
  $s.Write([System.BitConverter]::GetBytes($v), 0, 8)
}

$null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile)
$out = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create,
                              [System.IO.FileAccess]::Write)
try {
  # 1. The stub PE image.
  $stubStream = [System.IO.File]::OpenRead($stubPath)
  try { $stubStream.CopyTo($out) } finally { $stubStream.Dispose() }

  # 2. Each payload file, recording its (offset, size) for the TOC.
  $entries = foreach ($f in $files) {
    $offset = [uint64]$out.Position
    $in = [System.IO.File]::OpenRead($f.FullName)
    try { $in.CopyTo($out) } finally { $in.Dispose() }
    [pscustomobject]@{ Name = $f.Name; Offset = $offset; Size = [uint64]$f.Length }
  }

  # 3. The table of contents.
  $tocOffset = [uint64]$out.Position
  Write-UInt32 $out ([uint32]$entries.Count)
  foreach ($e in $entries) {
    $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($e.Name)
    Write-UInt32 $out ([uint32]$nameBytes.Length)
    $out.Write($nameBytes, 0, $nameBytes.Length)
    Write-UInt64 $out $e.Offset
    Write-UInt64 $out $e.Size
  }
  $tocSize = [uint64]$out.Position - $tocOffset

  # 4. The fixed footer: magic, then TOC offset and size.
  $out.Write($Magic, 0, $Magic.Length)
  Write-UInt64 $out $tocOffset
  Write-UInt64 $out $tocSize
}
finally {
  $out.Dispose()
}

Write-Host "Wrote $OutFile ($([math]::Round((Get-Item $OutFile).Length / 1GB, 2)) GiB)"

if ($SignCommand) {
  Write-Host "Signing $OutFile"
  # Sign last so the certificate table lands after the payload/footer; the
  # stub locates the footer relative to the certificate table, so this is safe.
  Invoke-Expression "$SignCommand `"$OutFile`""
}
