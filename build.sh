#!/usr/bin/env bash
set -eu
cd -- "$(dirname -- "$0")"
for arch in x64 x86; do
  if [ "$arch" = x64 ]; then prefix=x86_64-w64-mingw32; hde=hde64; extra='-Wl,--high-entropy-va'; else prefix=i686-w64-mingw32; hde=hde32; extra=''; fi
  mkdir -p "$arch" ".build/$arch"
  "$prefix-windres" -Isrc src/worker.rc -O coff -o ".build/$arch/manifest.o"
  for unit in buffer hook trampoline "hde/$hde"; do
    name=$(basename "$unit")
    "$prefix-gcc" -std=c11 -O2 -Wall -Wextra -c "vendor/minhook/src/$unit.c" -o ".build/$arch/$name.o"
  done
  "$prefix-g++" -std=c++20 -O2 -Wall -Wextra -Werror -static -municode -Wl,--dynamicbase,--nxcompat,--no-insert-timestamp $extra -s src/worker.cpp ".build/$arch/manifest.o" -o "$arch/FolderSizeWorker.exe"
  "$prefix-g++" -std=c++20 -O2 -Wall -Wextra -Werror -static -shared -Wl,--dynamicbase,--nxcompat,--kill-at,--no-insert-timestamp $extra -s src/bridge.cpp ".build/$arch/buffer.o" ".build/$arch/hook.o" ".build/$arch/trampoline.o" ".build/$arch/$hde.o" -lole32 -loleaut32 -lpropsys -lshell32 -lshlwapi -luuid -o "$arch/FolderSizeGuardBridge.dll"
  "$prefix-g++" -std=c++20 -O2 -Wall -Wextra -Werror -static -municode -mwindows -Wl,--dynamicbase,--nxcompat,--no-insert-timestamp $extra -s src/controller.cpp ".build/$arch/manifest.o" -lcomctl32 -lwinhttp -ldbghelp -lshell32 -lshlwapi -lole32 -ladvapi32 -luuid -o "$arch/FolderSizeGuard.exe"
done
