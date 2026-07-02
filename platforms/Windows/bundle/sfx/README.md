# Self-extracting offline installer (prototype)

A small native wrapper that folds the offline bundle — `installer.exe` plus
its loose `.msi`/`.cab` payloads — into a single self-extracting `.exe`,
sidestepping Burn's ~2 GiB attached-cabinet limit.

## Why this exists

The `offline` bundle flavor embeds every package into one attached cabinet
(`bundle-attached.cab`). Once the toolchain payload crosses ~2 GiB, that
cabinet exceeds the Microsoft Cabinet format limit and `wix build` fails with
`failed to compress cabinet ... (0x80004005)`.

This wrapper takes a different route:

1. Build the bundle with an **external-payload** flavor (`offline-sfx`), so
   `installer.exe` *references* the loose cabs instead of embedding them — no
   single oversized cabinet is ever produced.
2. Append those loose files to a native stub (`sfx.exe`) as a flat, stored
   (uncompressed — the cabs are already compressed) payload. The stub's
   container uses 64-bit offsets, so there is no 2 GiB ceiling.

At runtime the stub extracts the payload to a temp directory, launches the
extracted `installer.exe` **forwarding its command line verbatim**, waits, and
returns the installer's exit code. In `/quiet`, `/passive`, or
console-launched runs it suppresses the progress window and stays silent, so
it is transparent to automation.

## Files

| File | Purpose |
| --- | --- |
| `sfx.cc` | The stub: payload locator, extractor + progress UI, arg/exit-code passthrough. |
| `sfx.vcxproj` | Builds `sfx.exe` (GUI-subsystem, static CRT), mirroring `baf`. |
| `sfx.rc` / `resource.h` | App icon (reuses the bundle `logo.ico`). |
| `pack-sfx.ps1` | Assembles `stub + payload + TOC + footer` into the final `.exe`, optional signing. |

## Build & package

From the Windows build environment (PowerShell):

```powershell
# 1. Build the bundle with external payloads (no embedded mega-cab).
msbuild -nologo -restore -maxCpuCount `
  -p:Configuration=Release `
  -p:BundleFlavor=offline-sfx `
  -p:ProductArchitecture=amd64 `
  -p:Platforms="android;windows" `
  -p:ToolchainVariants="asserts;noasserts" `
  ...rest of your usual bundle args... `
  platforms\Windows\bundle\installer.wixproj

# 2. Build the SFX stub. (-restore because, like baf, this project inherits
#    the shared Directory.Build.targets references.)
msbuild -nologo -restore platforms\Windows\bundle\sfx\sfx.vcxproj `
  -p:Configuration=Release -p:Platform=x64

# 3. Fold installer.exe + the loose cabs into one self-extracting exe.
#    (BinaryCache/installer/Release/amd64 is the bundle's output directory —
#     point -PayloadDir at wherever your build emits installer.exe + *.cab.)
platforms\Windows\bundle\sfx\pack-sfx.ps1 `
  -Stub       <path>\sfx.exe `
  -PayloadDir <path>\Release\amd64 `
  -OutFile    <path>\swift-toolchain-offline.exe
```

To sign (sign **last** — the stub finds its footer relative to the certificate
table, so signing after packaging is safe):

```powershell
pack-sfx.ps1 ... -SignCommand '"C:\Path\signtool.exe" sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /f cert.pfx /p pw'
```

Also sign the inner `installer.exe` (as part of the normal bundle build) so
both layers are trusted.

## Notes / known caveats

- **Temp disk.** Extraction writes the full payload (~2 GiB) to `%TEMP%`
  before install, on top of Burn's own package cache. Machines tight on `C:`
  could fail mid-install.
- **SmartScreen.** A fresh ~2 GiB signed binary still needs reputation; an EV
  certificate avoids the initial warning.
- **Payload format** is defined once in `sfx.cc` (see the header comment) and
  must stay in sync with `pack-sfx.ps1`.
- This is a prototype for evaluation; it has not been wired into CI.
