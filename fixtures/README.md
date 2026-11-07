# Fixtures

Two minimal, harmless PE files used by the README and by manual tests.

| File | Format | Subsystem | Built with |
|---|---|---|---|
| `hello32.exe` | PE32 | console | `i686-w64-mingw32-gcc` |
| `hello64.exe` | PE32+ | console | `x86_64-w64-mingw32-gcc` |

Both are built from `hello.c` with:

```bash
make
```

The linker flag `--no-insert-timestamp` sets `TimeDateStamp` to `0`, so the
header output is reproducible across builds. The files contain no malicious
code: they only print a string and exit.
