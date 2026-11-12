# Fixtures

Three minimal, harmless PE files used by the README and by manual tests.

| File | Format | Subsystem | Built with |
|---|---|---|---|
| `hello32.exe` | PE32 | console | `i686-w64-mingw32-gcc` |
| `hello64.exe` | PE32+ | console | `x86_64-w64-mingw32-gcc` |
| `hello-net.exe` | PE32 (.NET) | console | `mcs` (Mono) |

`hello32.exe` and `hello64.exe` are built from `hello.c`, and `hello-net.exe`
from `hello.cs`, with:

```bash
make
```

The linker flag `--no-insert-timestamp` sets `TimeDateStamp` to `0`, so the
header output is reproducible across builds. The files contain no malicious
code: they only print a string and exit.
