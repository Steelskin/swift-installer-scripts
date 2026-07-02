// Copyright © 2026 Saleem Abdulrasool <compnerd@compnerd.org>
// SPDX-License-Identifier: Apache-2.0

// Self-extracting wrapper for the offline Swift toolchain installer.
//
// The build appends a flat payload (the Burn bundle's installer.exe plus
// every external .msi/.cab it references) to the end of this stub, followed
// by a table of contents and a fixed footer. At runtime the stub locates
// that payload, extracts it to a fresh temp directory, launches the
// extracted installer.exe forwarding our command line verbatim, waits, and
// returns the installer's exit code.
//
// Why a custom stub rather than a 7-Zip SFX: we need to forward arbitrary
// Burn switches (/quiet, /log, INSTALLROOT=..., etc.) untouched, and the
// payload is already high-compressed cabinets, so the wrapper needs no
// compression code at all — extraction is a plain byte copy.
//
// Payload layout (appended after the PE image, before any Authenticode
// certificate table):
//
//   [ stub PE image                                              ]
//   [ file 0 bytes ][ file 1 bytes ] ... [ file N-1 bytes        ]
//   [ TOC: u32 count, then per entry { u32 nameLen, name (UTF-8),
//          u64 offset, u64 size } (all little-endian)            ]
//   [ footer: char magic[8], u64 tocOffset, u64 tocSize          ]
//   [ (optional) Authenticode certificate table                  ]
//
// The footer is found relative to the *end of the overlay* — i.e. just
// before the certificate table if the stub is signed, or at EOF if not —
// so signing the finished exe does not move it. See LocateOverlayEnd.

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <CommCtrl.h>
#include <objbase.h>
#include <shellapi.h>

#include <cstdint>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>

#pragma comment(linker,                                                        \
    "/manifestdependency:\"type='win32' "                                      \
    "name='Microsoft.Windows.Common-Controls' version='6.0.0.0' "             \
    "processorArchitecture='*' publicKeyToken='6595b64144ccf1df' "            \
    "language='*'\"")

#include "resource.h"

namespace {

// MARK: - Payload format

constexpr char kMagic[8] = {'S', 'W', 'I', 'F', 'T', 'S', 'F', 'X'};
constexpr DWORD kFooterSize = sizeof(kMagic) + sizeof(uint64_t) * 2;

// The bundle entry point we hand off to once everything is extracted.
constexpr wchar_t kLaunchTarget[] = L"installer.exe";

constexpr wchar_t kWindowClass[] = L"SwiftToolkitSfxWindow";
constexpr wchar_t kWindowTitle[] = L"Swift toolchain installer";
constexpr wchar_t kStatusText[] = L"Preparing the Swift toolchain installer…";

constexpr UINT WM_APP_PROGRESS = WM_APP + 1;  // wParam = permille (0..1000)
constexpr UINT WM_APP_DONE = WM_APP + 2;      // wParam = 1 on success, 0 on error

struct Entry {
  std::wstring name;
  uint64_t offset = 0;
  uint64_t size = 0;
};

struct Payload {
  std::vector<Entry> entries;
  uint64_t total_bytes = 0;
};

// MARK: - Low-level file helpers

bool ReadExactAt(HANDLE file, uint64_t offset, void *buffer, DWORD length) {
  LARGE_INTEGER position;
  position.QuadPart = static_cast<LONGLONG>(offset);
  if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN))
    return false;

  auto *cursor = static_cast<BYTE *>(buffer);
  DWORD remaining = length;
  while (remaining) {
    DWORD read = 0;
    if (!ReadFile(file, cursor, remaining, &read, nullptr) || read == 0)
      return false;
    cursor += read;
    remaining -= read;
  }
  return true;
}

// Returns the byte offset at which the overlay ends: the start of the
// Authenticode certificate table if the stub is signed, otherwise the file
// size. Anything appended by signtool lands after this point, so the footer
// we read at (overlay_end - kFooterSize) is stable across signing.
bool LocateOverlayEnd(HANDLE file, uint64_t *overlay_end) {
  LARGE_INTEGER size;
  if (!GetFileSizeEx(file, &size))
    return false;
  *overlay_end = static_cast<uint64_t>(size.QuadPart);

  IMAGE_DOS_HEADER dos{};
  if (!ReadExactAt(file, 0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
    return false;

  IMAGE_NT_HEADERS64 nt{};
  if (!ReadExactAt(file, static_cast<uint64_t>(dos.e_lfanew), &nt, sizeof(nt)))
    return false;
  if (nt.Signature != IMAGE_NT_SIGNATURE ||
      nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    return true;  // Not a PE32+ image we recognise; fall back to EOF.

  const IMAGE_DATA_DIRECTORY &security =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
  // For the security directory, VirtualAddress is a *file offset*, not an RVA.
  if (security.VirtualAddress != 0 && security.Size != 0)
    *overlay_end = security.VirtualAddress;
  return true;
}

bool ParsePayload(HANDLE file, Payload *payload) {
  uint64_t overlay_end = 0;
  if (!LocateOverlayEnd(file, &overlay_end) || overlay_end < kFooterSize)
    return false;

  BYTE footer[kFooterSize];
  if (!ReadExactAt(file, overlay_end - kFooterSize, footer, kFooterSize))
    return false;
  if (memcmp(footer, kMagic, sizeof(kMagic)) != 0)
    return false;

  uint64_t toc_offset = 0;
  uint64_t toc_size = 0;
  memcpy(&toc_offset, footer + sizeof(kMagic), sizeof(toc_offset));
  memcpy(&toc_size, footer + sizeof(kMagic) + sizeof(toc_offset), sizeof(toc_size));
  if (toc_size == 0 || toc_offset + toc_size > overlay_end)
    return false;

  std::vector<BYTE> toc(static_cast<size_t>(toc_size));
  if (!ReadExactAt(file, toc_offset, toc.data(), static_cast<DWORD>(toc_size)))
    return false;

  size_t cursor = 0;
  auto take = [&](void *out, size_t n) {
    if (cursor + n > toc.size())
      return false;
    memcpy(out, toc.data() + cursor, n);
    cursor += n;
    return true;
  };

  uint32_t count = 0;
  if (!take(&count, sizeof(count)))
    return false;

  for (uint32_t i = 0; i < count; ++i) {
    uint32_t name_len = 0;
    if (!take(&name_len, sizeof(name_len)) || cursor + name_len > toc.size())
      return false;
    int wide_len = MultiByteToWideChar(CP_UTF8, 0,
        reinterpret_cast<const char *>(toc.data() + cursor),
        static_cast<int>(name_len), nullptr, 0);
    std::wstring name(static_cast<size_t>(wide_len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0,
        reinterpret_cast<const char *>(toc.data() + cursor),
        static_cast<int>(name_len), name.data(), wide_len);
    cursor += name_len;

    Entry entry;
    entry.name = std::move(name);
    if (!take(&entry.offset, sizeof(entry.offset)) ||
        !take(&entry.size, sizeof(entry.size)))
      return false;
    payload->total_bytes += entry.size;
    payload->entries.push_back(std::move(entry));
  }
  return !payload->entries.empty();
}

// MARK: - Extraction

struct ExtractContext {
  std::wstring self_path;
  std::wstring target_dir;
  const Payload *payload = nullptr;
  HWND window = nullptr;  // null in silent mode
};

bool ExtractAll(const ExtractContext &ctx) {
  HANDLE source = CreateFileW(ctx.self_path.c_str(), GENERIC_READ,
      FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (source == INVALID_HANDLE_VALUE)
    return false;

  std::vector<BYTE> buffer(1u << 20);  // 1 MiB copy buffer.
  uint64_t done = 0;
  int last_permille = -1;
  bool ok = true;

  for (const Entry &entry : ctx.payload->entries) {
    std::wstring path = ctx.target_dir + L"\\" + entry.name;
    HANDLE dest = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (dest == INVALID_HANDLE_VALUE) {
      ok = false;
      break;
    }

    LARGE_INTEGER position;
    position.QuadPart = static_cast<LONGLONG>(entry.offset);
    if (!SetFilePointerEx(source, position, nullptr, FILE_BEGIN)) {
      CloseHandle(dest);
      ok = false;
      break;
    }

    uint64_t remaining = entry.size;
    while (remaining) {
      DWORD chunk = static_cast<DWORD>(
          remaining < buffer.size() ? remaining : buffer.size());
      DWORD read = 0;
      if (!ReadFile(source, buffer.data(), chunk, &read, nullptr) || read == 0) {
        ok = false;
        break;
      }
      DWORD written = 0;
      if (!WriteFile(dest, buffer.data(), read, &written, nullptr) ||
          written != read) {
        ok = false;
        break;
      }
      remaining -= read;
      done += read;

      if (ctx.window) {
        int permille = ctx.payload->total_bytes
            ? static_cast<int>(done * 1000 / ctx.payload->total_bytes)
            : 1000;
        if (permille != last_permille) {
          last_permille = permille;
          PostMessageW(ctx.window, WM_APP_PROGRESS, permille, 0);
        }
      }
    }
    CloseHandle(dest);
    if (!ok)
      break;
  }

  CloseHandle(source);
  return ok;
}

DWORD WINAPI ExtractThread(LPVOID parameter) {
  auto *ctx = static_cast<ExtractContext *>(parameter);
  bool ok = ExtractAll(*ctx);
  PostMessageW(ctx->window, WM_APP_DONE, ok ? 1 : 0, 0);
  return ok ? 0 : 1;
}

// MARK: - Progress window

HWND g_progress_bar = nullptr;

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam,
                            LPARAM lparam) {
  switch (message) {
  case WM_CREATE: {
    HINSTANCE instance =
        reinterpret_cast<LPCREATESTRUCTW>(lparam)->hInstance;
    CreateWindowExW(0, WC_STATICW, kStatusText, WS_CHILD | WS_VISIBLE,
        20, 20, 420, 20, window, nullptr, instance, nullptr);
    g_progress_bar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 20, 52, 420, 22, window,
        nullptr, instance, nullptr);
    SendMessageW(g_progress_bar, PBM_SETRANGE32, 0, 1000);
    return 0;
  }
  case WM_APP_PROGRESS:
    SendMessageW(g_progress_bar, PBM_SETPOS, wparam, 0);
    return 0;
  case WM_APP_DONE:
    PostQuitMessage(wparam ? 0 : 1);
    return 0;
  case WM_CLOSE:
    // Ignore the user's attempt to close mid-extraction; it is quick.
    return 0;
  case WM_DESTROY:
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}

// Runs the extraction behind a small themed progress window. Returns true on
// success. The window is torn down before we hand off to the installer.
bool ExtractWithUI(HINSTANCE instance, ExtractContext *ctx) {
  INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_PROGRESS_CLASS};
  InitCommonControlsEx(&icc);

  WNDCLASSEXW wc{};
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = WindowProc;
  wc.hInstance = instance;
  wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_APPICON));
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
  wc.lpszClassName = kWindowClass;
  RegisterClassExW(&wc);

  const int width = 480;
  const int height = 140;
  const int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
  const int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;
  HWND window = CreateWindowExW(0, kWindowClass, kWindowTitle,
      WS_CAPTION | WS_SYSMENU | WS_VISIBLE, x, y, width, height, nullptr,
      nullptr, instance, nullptr);
  if (!window)
    return ExtractAll(*ctx);  // Fall back to headless extraction.

  ctx->window = window;
  HANDLE thread = CreateThread(nullptr, 0, ExtractThread, ctx, 0, nullptr);
  if (!thread) {
    DestroyWindow(window);
    return false;
  }

  MSG message;
  bool success = false;
  while (GetMessageW(&message, nullptr, 0, 0)) {
    if (message.message == WM_QUIT)
      break;
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }
  // The quit code carries success; GetMessage already consumed WM_QUIT, so
  // recover it from the thread's result instead.
  WaitForSingleObject(thread, INFINITE);
  DWORD exit_code = 1;
  GetExitCodeThread(thread, &exit_code);
  success = exit_code == 0;
  CloseHandle(thread);

  DestroyWindow(window);
  UnregisterClassW(kWindowClass, instance);
  return success;
}

// MARK: - Command-line forwarding

// Returns everything in our command line after argv[0], so the installer
// receives the caller's switches verbatim (quoting preserved).
std::wstring ForwardedArguments() {
  const wchar_t *cursor = GetCommandLineW();
  if (*cursor == L'"') {
    ++cursor;
    while (*cursor && *cursor != L'"')
      ++cursor;
    if (*cursor == L'"')
      ++cursor;
  } else {
    while (*cursor && !iswspace(*cursor))
      ++cursor;
  }
  while (*cursor && iswspace(*cursor))
    ++cursor;
  return std::wstring(cursor);
}

bool WantsSilent() {
  int count = 0;
  LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &count);
  if (!argv)
    return false;
  bool silent = false;
  for (int i = 1; i < count && !silent; ++i) {
    const wchar_t *arg = argv[i];
    if (*arg == L'/' || *arg == L'-')
      ++arg;
    // lstrcmpiW lives in windows.h, avoiding a CRT <string.h> dependency.
    silent = lstrcmpiW(arg, L"quiet") == 0 || lstrcmpiW(arg, L"q") == 0 ||
             lstrcmpiW(arg, L"silent") == 0 || lstrcmpiW(arg, L"s") == 0 ||
             lstrcmpiW(arg, L"passive") == 0;
  }
  LocalFree(argv);
  return silent;
}

// MARK: - Temp directory lifecycle

std::wstring MakeTempDir() {
  wchar_t base[MAX_PATH];
  DWORD length = GetTempPathW(MAX_PATH, base);
  if (length == 0 || length > MAX_PATH)
    return {};

  GUID guid;
  if (CoCreateGuid(&guid) != S_OK)
    return {};
  wchar_t guid_text[40];
  StringFromGUID2(guid, guid_text, 40);

  std::wstring dir = std::wstring(base) + L"SwiftToolkit-" + guid_text;
  if (!CreateDirectoryW(dir.c_str(), nullptr))
    return {};
  return dir;
}

void RemoveTempDir(const std::wstring &dir, const Payload &payload) {
  // The payload is flat (no nested directories), so deleting each extracted
  // file and then the directory is sufficient and avoids a recursive walk.
  for (const Entry &entry : payload.entries)
    DeleteFileW((dir + L"\\" + entry.name).c_str());
  RemoveDirectoryW(dir.c_str());
}

void ReportError(bool silent, const wchar_t *text) {
  if (silent) {
    if (AttachConsole(ATTACH_PARENT_PROCESS) || GetStdHandle(STD_ERROR_HANDLE)) {
      DWORD written = 0;
      std::wstring line = std::wstring(text) + L"\r\n";
      WriteConsoleW(GetStdHandle(STD_ERROR_HANDLE), line.c_str(),
          static_cast<DWORD>(line.size()), &written, nullptr);
    }
  } else {
    MessageBoxW(nullptr, text, kWindowTitle, MB_ICONERROR | MB_OK);
  }
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int) {
  const bool silent = WantsSilent();

  wchar_t self[MAX_PATH];
  if (!GetModuleFileNameW(nullptr, self, MAX_PATH)) {
    ReportError(silent, L"Unable to determine the running executable path.");
    return 1;
  }

  HANDLE file = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, nullptr,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    ReportError(silent, L"Unable to open the installer package for reading.");
    return 1;
  }

  Payload payload;
  bool parsed = ParsePayload(file, &payload);
  CloseHandle(file);
  if (!parsed) {
    ReportError(silent, L"This file does not contain a valid installer payload.");
    return 1;
  }

  std::wstring target_dir = MakeTempDir();
  if (target_dir.empty()) {
    ReportError(silent, L"Unable to create a temporary extraction directory.");
    return 1;
  }

  ExtractContext ctx;
  ctx.self_path = self;
  ctx.target_dir = target_dir;
  ctx.payload = &payload;

  bool extracted = silent ? ExtractAll(ctx) : ExtractWithUI(instance, &ctx);
  if (!extracted) {
    RemoveTempDir(target_dir, payload);
    ReportError(silent, L"Failed to extract the installer payload (out of disk space?).");
    return 1;
  }

  std::wstring installer = target_dir + L"\\" + kLaunchTarget;
  std::wstring command = L"\"" + installer + L"\"";
  std::wstring forwarded = ForwardedArguments();
  if (!forwarded.empty())
    command += L" " + forwarded;

  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');

  STARTUPINFOW startup{sizeof(startup)};
  PROCESS_INFORMATION process{};
  DWORD exit_code = 1;
  if (CreateProcessW(installer.c_str(), mutable_command.data(), nullptr,
          nullptr, FALSE, 0, nullptr, target_dir.c_str(), &startup, &process)) {
    WaitForSingleObject(process.hProcess, INFINITE);
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
  } else {
    ReportError(silent, L"Failed to launch the extracted installer.");
  }

  RemoveTempDir(target_dir, payload);
  return static_cast<int>(exit_code);
}
