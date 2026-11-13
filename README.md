# pe-inspect

A small, dependency-free PE header inspector written in Rust. It reads the DOS
header, the PE signature, the COFF file header, the optional header (PE32 and
PE32+), and the data directory table. It is the first stage of a larger PE
analysis tool built as part of a red team / vulnerability research study plan.

## Features

- Parses **PE32** (`Magic = 0x10B`) and **PE32+** (`Magic = 0x20B`).
- Reads all values with bounds-checked little-endian helpers.
- Prints decoded `Machine`, `Subsystem`, `Characteristics`, and data directory
  names instead of raw numbers only.
- Uses `NumberOfRvaAndSizes` and the declared optional-header size to decide how
  many data directory entries are valid.
- Prints the sections table with names, VirtualSize, RVA, SizeOfRawData, 
  PointerToRawData, entropy and flags.
- Returns a clear error and exit code `1` for non-PE or truncated files; it does
  not panic on malformed input.
- No external crates: standard library only.

## Requirements

- Rust stable with edition 2024 support (Rust 1.85 or newer).
- No external dependencies.

## Build

```bash
cargo build --release
```

## Usage

```bash
./target/release/pe-inspect --headers <file>
./target/release/pe-inspect --sections <file>
```

Examples:

`--help` prints the usage summary.

## Example output --headers flag

```bash
./target/release/pe-inspect --headers fixtures/hello64.exe
```

Output for the included `fixtures/hello64.exe`:

```text
Archivo: fixtures/hello64.exe (145036 bytes)

DOS header
  e_magic              0x5A4D (MZ)
  e_lfanew             0x00000080 (128)

Firma PE   0x00004550 (PE\0\0) en 0x00000080

COFF header en 0x00000084
  Machine              0x8664 (x64)
  NumberOfSections     19
  TimeDateStamp        0x00000000 (0; puede ser hash de build)
  PointerToSymbolTable 0x00019C00
  NumberOfSymbols      1829
  SizeOfOptionalHeader 0x00F0 (240 bytes)
  Characteristics      0x0026 (EXECUTABLE_IMAGE | LINE_NUMS_STRIPPED | LARGE_ADDRESS_AWARE)

Optional header en 0x00000098 (240 bytes)
  Magic                0x020B (PE32+)
  AddressOfEntryPoint  0x00001440 (5184)
  BaseOfCode           0x00001000
  ImageBase            0x140000000
  SectionAlignment     0x1000
  FileAlignment        0x200
  SizeOfImage          0x27000
  SizeOfHeaders        0x600
  Subsystem            3 (WINDOWS_CUI)
  DllCharacteristics   0x0160
  NumberOfRvaAndSizes  16
  DataDirectory        0x00000108 (16 entradas)
  Data directories:
    [ 0] Export             -
    [ 1] Import             0x00009000 / 0x00000908
    [ 2] Resource           -
    [ 3] Exception          0x00006000 / 0x00000234
    [ 4] Certificate        -
    [ 5] Base Relocation    0x0000B000 / 0x00000060
    [ 6] Debug              -
    [ 7] Architecture       -
    [ 8] Global Ptr         -
    [ 9] TLS                0x00004080 / 0x00000028
    [10] Load Config        -
    [11] Bound Import       -
    [12] IAT                0x00009280 / 0x000001B8
    [13] Delay Import       -
    [14] CLR Runtime        -
    [15] Reserved           -
```

## Example output --sections flag

```bash
./target/release/pe-inspect --sections fixtures/hello64.exe
```

Output for the included `fixtures/hello64.exe`:

```text
Archivo: fixtures/hello64.exe (145036 bytes)

Sections (19)
  Idx  Name        VSize       RVA         RawSize     RawPtr      Entropy  Characteristics
    0  .text       0x00001B40  0x00001000  0x00001C00  0x00000600     5.85  0x60000020 (CNT_CODE | MEM_EXECUTE | MEM_READ)
    1  .data       0x000000C0  0x00003000  0x00000200  0x00002200     0.61  0xC0000040 (CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE)
    2  .rdata      0x00000A08  0x00004000  0x00000C00  0x00002400     3.65  0x40000040 (CNT_INITIALIZED_DATA | MEM_READ)
    3  /4          0x00000004  0x00005000  0x00000200  0x00003000     0.00  0xC0000040 (CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE)
    4  .pdata      0x00000234  0x00006000  0x00000400  0x00003200     2.41  0x40000040 (CNT_INITIALIZED_DATA | MEM_READ)
    5  .xdata      0x000001BC  0x00007000  0x00000200  0x00003600     3.50  0x40000040 (CNT_INITIALIZED_DATA | MEM_READ)
    6  .bss        0x000001E0  0x00008000  0x00000000  0x00000000     0.00  0xC0000080 (CNT_UNINITIALIZED_DATA | MEM_READ | MEM_WRITE)
    7  .idata      0x00000908  0x00009000  0x00000A00  0x00003800     3.74  0x40000040 (CNT_INITIALIZED_DATA | MEM_READ)
    8  .tls        0x00000010  0x0000A000  0x00000200  0x00004200     0.00  0xC0000040 (CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE)
    9  .reloc      0x00000060  0x0000B000  0x00000200  0x00004400     1.26  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
   10  /14         0x00000500  0x0000C000  0x00000600  0x00004600     1.46  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
   11  /29         0x0000C116  0x0000D000  0x0000C200  0x00004C00     5.92  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
   12  /41         0x00002088  0x0001A000  0x00002200  0x00010E00     4.72  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
   13  /55         0x00001F71  0x0001D000  0x00002000  0x00013000     4.92  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
   14  /67         0x00000880  0x0001F000  0x00000A00  0x00015000     3.65  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
   15  /80         0x00000387  0x00020000  0x00000400  0x00015A00     4.83  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
   16  /91         0x000025FB  0x00021000  0x00002600  0x00015E00     4.66  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
   17  /107        0x000014E5  0x00024000  0x00001600  0x00018400     4.96  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
   18  /123        0x0000018C  0x00026000  0x00000200  0x00019A00     4.05  0x42000040 (CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ)
```


## Tests

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

The unit tests build a synthetic PE in memory and cover:

- valid PE32+ headers and data directory entries;
- a non-PE input;
- an unknown optional-header `Magic`;
- a truncated optional header;
- `NumberOfRvaAndSizes` smaller than 16;
- `NumberOfRvaAndSizes` larger than 16 (capped at 16);
- a valid sections table;
- a truncated section table;
- zero sections;
- entropy of empty and all-zero data is 0;
- entropy of two equiprobable values is 1;
- entropy of all 256 byte values is 8.

## Error handling

```text
$ ./target/release/pe-inspect --headers /tmp/not-a-pe.bin
error: no es un PE: e_magic = 0x0000, se esperaba 0x5A4D (MZ)
$ echo $?
1

$ ./target/release/pe-inspect --headers --sections <archivo>
error: uso: pe-inspect --headers|--sections <archivo>
$ echo $?
1
```

## Fixtures

`fixtures/hello32.exe`, `fixtures/hello64.exe` and `fixtures/hello-net.exe` are minimal "hello world"
programs built with mingw-w64 and mcs from `fixtures/hello.c` and `fixtures/hello.cs` respectively. 
They are harmless and are included so anyone can clone the repo and reproduce the output above. 
The linker flag `--no-insert-timestamp` keeps `TimeDateStamp` at `0`. Regenerate them with:

```bash
cd fixtures && make
```

`hello-net.exe` is a .NET (PE32 + CLR) assembly.

## Limitations and next steps

- Imports, exports, and resources are not parsed yet.
- The output is a human-readable report, not JSON.

## Repository layout

```text
.
├── Cargo.lock
├── Cargo.toml
├── create_txt.sh
├── docs/design-notes.md
├── fixtures
│   ├── hello32.exe
│   ├── hello64.exe
│   ├── hello.c
│   ├── hello.cs
│   ├── hello-net.exe
│   ├── Makefile
│   └── README.md
├── README.md
├── src/main.rs

```

## Design notes

See [docs/design-notes.md](docs/design-notes.md) for the decisions behind the
parser (std-only, bounds checks, raw timestamps, data directory limits).
