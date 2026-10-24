# Third-party notices

The application sources are distributed under GPL-3.0-only. See LICENSE.txt.

## Explorer hook adaptation

The exact Explorer symbol signatures, recursive operation guards, and
CDefCollection workaround are adapted from **Better file sizes in Explorer
details v1.6**, by **Michael Maltsev (m417z)**, licensed under GPL v3.0:

https://github.com/ramensoftware/windhawk-mods/blob/c89e4f4b2c154f31a7b6f5f80a164b2f24a288f6/mods/explorer-details-better-file-sizes.wh.cpp

The standalone implementation adds a native controller, owner/session checked
injection, Windows DbgHelp symbol resolution with Microsoft HTTPS retrieval,
MinHook integration, owner-process watchdog, separate metadata worker, bounded
cache and queue, conservative incomplete-result handling and self-test UI.
No Windhawk engine or SDK is linked or distributed in the executables.

## MinHook

MinHook **v1.3.4**, by Tsuda Kageyu and contributors, is statically linked into
the bridge DLL. The source and full license (including HDE notices) are included
under `vendor/minhook/`. No separate MinHook installation is required.

https://github.com/TsudaKageyu/minhook/tree/v1.3.4

## Runtime

MinGW-w64 and GCC C++ runtime components are statically linked. Their copyright
and runtime-exception notices are under `licenses/`. Microsoft system DLLs are
used from the installed Windows OS and are not redistributed.

## Primary references

- https://learn.microsoft.com/en-us/windows/win32/debug/dbghelp-versions
- https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-imagehlp_module64
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfileexw
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
