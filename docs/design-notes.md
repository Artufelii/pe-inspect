# Design notes

Short record of the decisions behind `pe-inspect`. The goal is a readable,
auditable parser that fails cleanly, not a complete PE loader.

## Standard library only

The project has no dependencies. Every read is a few lines of code, and the
binary builds with a stock Rust toolchain. For a learning/portfolio tool this
keeps the supply chain empty and makes the parsing logic explicit.

## Bounds-checked readers

All multi-byte reads go through `read_u16`, `read_u32`, and `read_u64`. Each one:

1. computes `offset + width` with `checked_add`;
2. slices with `bytes.get(range)`;
3. returns `Error::OutOfBounds` or `Error::TooShort` instead of panicking.

This is why a random file, a truncated header, or a bad `e_lfanew` produces a
message and exit code `1` rather than a crash.

## Offset calculation

The parser follows the format literally:

```text
optional = e_lfanew + 4 (PE signature) + 20 (COFF header)
```

It never assumes `e_lfanew = 0x80`. The optional header size comes from
`SizeOfOptionalHeader`, not from the typical `0xE0` / `0xF0` values.

## PE32 vs PE32+

`Magic` decides the layout:

| Field | PE32 | PE32+ |
|---|---|---|
| `ImageBase` | 4 bytes at `0x1C` | 8 bytes at `0x18` |
| `NumberOfRvaAndSizes` | `0x5C` | `0x6C` |
| `DataDirectory` | `0x60` | `0x70` |

`ImageBase` is stored as `u64` in the struct so both variants share one type.

## Data directory limits

The table is an array of 8-byte entries, but the parser does not blindly read 16:

```text
count = min(NumberOfRvaAndSizes, 16, available_bytes / 8)
```

- `NumberOfRvaAndSizes` is the declared count.
- `16` is the maximum defined by the format.
- `available_bytes` is what actually fits inside `SizeOfOptionalHeader`.

This handles files that declare fewer entries, files that declare more than fit,
and truncated optional headers without reading past the buffer.

Entry `[4]` (`Certificate`) is the exception: its first field is a **file
offset**, not an RVA. The output marks it when non-zero.

## Raw `TimeDateStamp`

`TimeDateStamp` is printed as a raw 32-bit value. Modern linkers can use it as a
reproducible-build hash (for example `/Brepro`), so interpreting it as a date is
often wrong. The raw value is the honest representation.

## Fixtures

- Unit tests build a synthetic PE in memory. They do not depend on external
  files and can run anywhere.
- The `fixtures/` directory contains two real, harmless mingw-w64 builds so the
  README output is reproducible after a clone. `--no-insert-timestamp` keeps the
  output stable.

## Error model

Errors are a single `enum` with `Display` implementations. `main` prints
`error: ...` to stderr and returns `ExitCode::FAILURE`. There are no partial
prints: the file is parsed first, then the report is printed.

## Next step

Add the section table (`--sections`): name, virtual size, virtual address, raw
size, raw offset, characteristics, and Shannon entropy per section.
