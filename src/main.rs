use std::env;
use std::fmt;
use std::fs;
use std::process::ExitCode;

const DOS_HEADER_MIN: usize = 64;
const E_LFANEW_OFFSET: usize = 0x3C;
const PE_SIGNATURE: u32 = 0x0000_4550;
const COFF_SIZE: usize = 20;
const OPTIONAL_MAGIC_PE32: u16 = 0x010B;
const OPTIONAL_MAGIC_PE32_PLUS: u16 = 0x020B;
const DATA_DIRECTORY_ENTRIES: usize = 16;

#[derive(Debug)]
enum Error {
    Io(std::io::Error),
    Usage(&'static str),
    TooShort {
        what: &'static str,
        need: usize,
        got: usize,
    },
    OutOfBounds {
        offset: usize,
        need: usize,
        len: usize,
    },
    BadDosMagic(u16),
    BadPeSignature(u32),
    BadOptionalMagic(u16),
    OptionalHeaderTooSmall {
        size: usize,
        minimum: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "no se pudo leer el archivo: {e}"),
            Error::Usage(msg) => write!(f, "uso: {msg}"),
            Error::TooShort { what, need, got } => {
                write!(f, "{what} truncado: se necesitan {need} bytes y hay {got}")
            }
            Error::OutOfBounds { offset, need, len } => write!(
                f,
                "lectura fuera de rango en 0x{offset:X}: se necesitan {need} bytes y el archivo mide {len}"
            ),
            Error::BadDosMagic(m) => write!(
                f,
                "no es un PE: e_magic = 0x{m:04X}, se esperaba 0x5A4D (MZ)"
            ),
            Error::BadPeSignature(s) => write!(
                f,
                "firma PE inválida: 0x{s:08X}, se esperaba 0x00004550 (PE\\0\\0)"
            ),
            Error::BadOptionalMagic(m) => write!(
                f,
                "optional header desconocido: Magic = 0x{m:04X}, se esperaba 0x010B (PE32) o 0x020B (PE32+)"
            ),
            Error::OptionalHeaderTooSmall { size, minimum } => write!(
                f,
                "optional header de {size} bytes; se necesitan al menos {minimum}"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

#[derive(Debug)]
struct Headers {
    e_lfanew: usize,
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
    optional: OptionalHeader,
}

#[derive(Debug)]
struct DataDirectoryEntry {
    index: usize,
    rva: u32,
    size: u32,
}

impl DataDirectoryEntry {
    fn is_empty(&self) -> bool {
        self.rva == 0 && self.size == 0
    }
}

#[derive(Debug)]
struct OptionalHeader {
    magic: u16,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    size_of_image: u32,
    size_of_headers: u32,
    subsystem: u16,
    dll_characteristics: u16,
    number_of_rva_and_sizes: u32,
    data_directory_offset: usize,
    data_directories: Vec<DataDirectoryEntry>,
}

impl OptionalHeader {
    fn is_pe32_plus(&self) -> bool {
        self.magic == OPTIONAL_MAGIC_PE32_PLUS
    }

    fn magic_name(&self) -> &'static str {
        if self.is_pe32_plus() { "PE32+" } else { "PE32" }
    }
}

type Result<T> = std::result::Result<T, Error>;

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset.checked_add(2).ok_or(Error::OutOfBounds {
        offset,
        need: 2,
        len: bytes.len(),
    })?;
    let slice = bytes.get(offset..end).ok_or(Error::OutOfBounds {
        offset,
        need: 2,
        len: bytes.len(),
    })?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::OutOfBounds {
        offset,
        need: 4,
        len: bytes.len(),
    })?;
    let slice = bytes.get(offset..end).ok_or(Error::OutOfBounds {
        offset,
        need: 4,
        len: bytes.len(),
    })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or(Error::OutOfBounds {
        offset,
        need: 8,
        len: bytes.len(),
    })?;
    let slice = bytes.get(offset..end).ok_or(Error::OutOfBounds {
        offset,
        need: 8,
        len: bytes.len(),
    })?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn parse_optional(
    bytes: &[u8],
    optional_start: usize,
    declared_size: u16,
) -> Result<OptionalHeader> {
    let declared_size = declared_size as usize;

    if declared_size < 2 {
        return Err(Error::OptionalHeaderTooSmall {
            size: declared_size,
            minimum: 2,
        });
    }

    let optional_end = optional_start
        .checked_add(declared_size)
        .ok_or(Error::OutOfBounds {
            offset: optional_start,
            need: declared_size,
            len: bytes.len(),
        })?;

    if optional_end > bytes.len() {
        return Err(Error::TooShort {
            what: "optional header",
            need: optional_end,
            got: bytes.len(),
        });
    }

    let magic = read_u16(bytes, optional_start)?;

    let (
        image_base_offset,
        image_base_size,
        number_of_rva_and_sizes_offset,
        data_directory_offset,
        minimum,
    ) = match magic {
        OPTIONAL_MAGIC_PE32 => (0x1C, 4, 0x5C, 0x60, 0x60),
        OPTIONAL_MAGIC_PE32_PLUS => (0x18, 8, 0x6C, 0x70, 0x70),
        other => return Err(Error::BadOptionalMagic(other)),
    };

    if declared_size < minimum {
        return Err(Error::OptionalHeaderTooSmall {
            size: declared_size,
            minimum,
        });
    }

    let image_base = if image_base_size == 8 {
        read_u64(bytes, optional_start + image_base_offset)?
    } else {
        read_u32(bytes, optional_start + image_base_offset)? as u64
    };

    let number_of_rva_and_sizes = read_u32(bytes, optional_start + number_of_rva_and_sizes_offset)?;
    let data_directory_offset = optional_start + data_directory_offset;

    // Solo existen las entradas que caben dentro del optional header declarado.
    let available_entries = (optional_end - data_directory_offset) / 8;
    let entry_count = (number_of_rva_and_sizes as usize)
        .min(DATA_DIRECTORY_ENTRIES)
        .min(available_entries);

    let mut data_directories = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let entry_offset = data_directory_offset + index * 8;
        data_directories.push(DataDirectoryEntry {
            index,
            rva: read_u32(bytes, entry_offset)?,
            size: read_u32(bytes, entry_offset + 4)?,
        });
    }

    Ok(OptionalHeader {
        magic,
        address_of_entry_point: read_u32(bytes, optional_start + 0x10)?,
        base_of_code: read_u32(bytes, optional_start + 0x14)?,
        image_base,
        section_alignment: read_u32(bytes, optional_start + 0x20)?,
        file_alignment: read_u32(bytes, optional_start + 0x24)?,
        size_of_image: read_u32(bytes, optional_start + 0x38)?,
        size_of_headers: read_u32(bytes, optional_start + 0x3C)?,
        subsystem: read_u16(bytes, optional_start + 0x44)?,
        dll_characteristics: read_u16(bytes, optional_start + 0x46)?,
        number_of_rva_and_sizes,
        data_directory_offset,
        data_directories,
    })
}

fn parse(bytes: &[u8]) -> Result<Headers> {
    if bytes.len() < DOS_HEADER_MIN {
        return Err(Error::TooShort {
            what: "DOS header",
            need: DOS_HEADER_MIN,
            got: bytes.len(),
        });
    }

    let magic = read_u16(bytes, 0)?;
    if magic != 0x5A4D {
        return Err(Error::BadDosMagic(magic));
    }

    let e_lfanew = read_u32(bytes, E_LFANEW_OFFSET)? as usize;
    let signature = read_u32(bytes, e_lfanew)?;
    if signature != PE_SIGNATURE {
        return Err(Error::BadPeSignature(signature));
    }

    let coff = e_lfanew + 4;
    if bytes.len() < coff + COFF_SIZE {
        return Err(Error::TooShort {
            what: "COFF header",
            need: coff + COFF_SIZE,
            got: bytes.len(),
        });
    }

    let size_of_optional_header = read_u16(bytes, coff + 16)?;
    let optional = parse_optional(bytes, coff + COFF_SIZE, size_of_optional_header)?;

    Ok(Headers {
        e_lfanew,
        machine: read_u16(bytes, coff)?,
        number_of_sections: read_u16(bytes, coff + 2)?,
        time_date_stamp: read_u32(bytes, coff + 4)?,
        pointer_to_symbol_table: read_u32(bytes, coff + 8)?,
        number_of_symbols: read_u32(bytes, coff + 12)?,
        size_of_optional_header,
        characteristics: read_u16(bytes, coff + 18)?,
        optional,
    })
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014C => "i386 (x86)",
        0x8664 => "x64",
        0xAA64 => "ARM64",
        0x01C0 => "ARM",
        0x0200 => "IA64",
        _ => "desconocida",
    }
}

fn characteristics_names(characteristics: u16) -> String {
    let flags = [
        (0x0001, "RELOCS_STRIPPED"),
        (0x0002, "EXECUTABLE_IMAGE"),
        (0x0004, "LINE_NUMS_STRIPPED"),
        (0x0008, "LOCAL_SYMS_STRIPPED"),
        (0x0010, "AGGRESSIVE_WS_TRIM"),
        (0x0020, "LARGE_ADDRESS_AWARE"),
        (0x0080, "BYTES_REVERSED_LO"),
        (0x0100, "32BIT_MACHINE"),
        (0x0200, "DEBUG_STRIPPED"),
        (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
        (0x0800, "NET_RUN_FROM_SWAP"),
        (0x1000, "SYSTEM"),
        (0x2000, "DLL"),
        (0x4000, "UP_SYSTEM_ONLY"),
        (0x8000, "BYTES_REVERSED_HI"),
    ];

    let mut names = Vec::new();
    for (bit, name) in flags {
        if characteristics & bit != 0 {
            names.push(name);
        }
    }

    if names.is_empty() {
        names.push("-");
    }
    names.join(" | ")
}

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "NATIVE",
        2 => "WINDOWS_GUI",
        3 => "WINDOWS_CUI",
        5 => "OS2_CUI",
        7 => "POSIX_CUI",
        9 => "WINDOWS_CE_GUI",
        10 => "EFI_APPLICATION",
        11 => "EFI_BOOT_SERVICE_DRIVER",
        12 => "EFI_RUNTIME_DRIVER",
        13 => "EFI_ROM",
        14 => "XBOX",
        16 => "WINDOWS_BOOT_APPLICATION",
        _ => "DESCONOCIDO",
    }
}

fn data_directory_name(index: usize) -> &'static str {
    match index {
        0 => "Export",
        1 => "Import",
        2 => "Resource",
        3 => "Exception",
        4 => "Certificate",
        5 => "Base Relocation",
        6 => "Debug",
        7 => "Architecture",
        8 => "Global Ptr",
        9 => "TLS",
        10 => "Load Config",
        11 => "Bound Import",
        12 => "IAT",
        13 => "Delay Import",
        14 => "CLR Runtime",
        15 => "Reserved",
        _ => "Desconocido",
    }
}

fn print_headers(path: &str, bytes: &[u8], headers: &Headers) {
    let coff = headers.e_lfanew + 4;
    let optional = coff + COFF_SIZE;

    println!("Archivo: {path} ({} bytes)", bytes.len());
    println!();
    println!("DOS header");
    println!("  {:<20} 0x5A4D (MZ)", "e_magic");
    println!(
        "  {:<20} 0x{:08X} ({})",
        "e_lfanew", headers.e_lfanew, headers.e_lfanew
    );
    println!();
    println!(
        "Firma PE   0x00004550 (PE\\0\\0) en 0x{:08X}",
        headers.e_lfanew
    );
    println!();
    println!("COFF header en 0x{coff:08X}");
    println!(
        "  {:<20} 0x{:04X} ({})",
        "Machine",
        headers.machine,
        machine_name(headers.machine)
    );
    println!(
        "  {:<20} {}",
        "NumberOfSections", headers.number_of_sections
    );
    println!(
        "  {:<20} 0x{:08X} ({}; puede ser hash de build)",
        "TimeDateStamp", headers.time_date_stamp, headers.time_date_stamp
    );
    println!(
        "  {:<20} 0x{:08X}",
        "PointerToSymbolTable", headers.pointer_to_symbol_table
    );
    println!("  {:<20} {}", "NumberOfSymbols", headers.number_of_symbols);
    println!(
        "  {:<20} 0x{:04X} ({} bytes)",
        "SizeOfOptionalHeader", headers.size_of_optional_header, headers.size_of_optional_header
    );
    println!(
        "  {:<20} 0x{:04X} ({})",
        "Characteristics",
        headers.characteristics,
        characteristics_names(headers.characteristics)
    );
    println!();
    println!(
        "Optional header en 0x{optional:08X} ({} bytes)",
        headers.size_of_optional_header
    );
    println!(
        "  {:<20} 0x{:04X} ({})",
        "Magic",
        headers.optional.magic,
        headers.optional.magic_name()
    );
    println!(
        "  {:<20} 0x{:08X} ({})",
        "AddressOfEntryPoint",
        headers.optional.address_of_entry_point,
        headers.optional.address_of_entry_point
    );
    println!(
        "  {:<20} 0x{:08X}",
        "BaseOfCode", headers.optional.base_of_code
    );
    println!("  {:<20} 0x{:X}", "ImageBase", headers.optional.image_base);
    println!(
        "  {:<20} 0x{:X}",
        "SectionAlignment", headers.optional.section_alignment
    );
    println!(
        "  {:<20} 0x{:X}",
        "FileAlignment", headers.optional.file_alignment
    );
    println!(
        "  {:<20} 0x{:X}",
        "SizeOfImage", headers.optional.size_of_image
    );
    println!(
        "  {:<20} 0x{:X}",
        "SizeOfHeaders", headers.optional.size_of_headers
    );
    println!(
        "  {:<20} {} ({})",
        "Subsystem",
        headers.optional.subsystem,
        subsystem_name(headers.optional.subsystem)
    );
    println!(
        "  {:<20} 0x{:04X}",
        "DllCharacteristics", headers.optional.dll_characteristics
    );
    println!(
        "  {:<20} {}",
        "NumberOfRvaAndSizes", headers.optional.number_of_rva_and_sizes
    );
    println!(
        "  {:<20} 0x{:08X} ({} entradas)",
        "DataDirectory",
        headers.optional.data_directory_offset,
        headers.optional.data_directories.len()
    );

    if !headers.optional.data_directories.is_empty() {
        println!("  Data directories:");

        for entry in &headers.optional.data_directories {
            let name = data_directory_name(entry.index);

            if entry.is_empty() {
                println!("    [{:>2}] {:<18} -", entry.index, name);
            } else {
                let suffix = if entry.index == 4 {
                    " (file offset)"
                } else {
                    ""
                };
                println!(
                    "    [{:>2}] {:<18} 0x{:08X} / 0x{:08X}{}",
                    entry.index, name, entry.rva, entry.size, suffix
                );
            }
        }
    }
}

fn print_usage() {
    println!("pe-inspect 0.1.0");
    println!();
    println!("Uso:");
    println!("  pe-inspect --headers <archivo>");
    println!();
    println!("Ejemplo:");
    println!("  pe-inspect --headers C:\\Windows\\System32\\notepad.exe");
}

fn run(args: &[String]) -> Result<()> {
    match args {
        [] => {
            print_usage();
            Ok(())
        }
        [flag] if flag.as_str() == "-h" || flag.as_str() == "--help" => {
            print_usage();
            Ok(())
        }
        [flag, path] if flag.as_str() == "--headers" => {
            let bytes = fs::read(path)?;
            let headers = parse(&bytes)?;
            print_headers(path, &bytes, &headers);
            Ok(())
        }
        _ => Err(Error::Usage("pe-inspect --headers <archivo>")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
        bytes[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");

        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&8u16.to_le_bytes());
        bytes[coff + 4..coff + 8].copy_from_slice(&0xD483ACA1u32.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&0x00F0u16.to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

        let opt = 0x98;
        bytes[opt..opt + 2].copy_from_slice(&OPTIONAL_MAGIC_PE32_PLUS.to_le_bytes());
        bytes[opt + 0x10..opt + 0x14].copy_from_slice(&0x1440u32.to_le_bytes());
        bytes[opt + 0x14..opt + 0x18].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[opt + 0x18..opt + 0x20].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        bytes[opt + 0x20..opt + 0x24].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[opt + 0x24..opt + 0x28].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[opt + 0x38..opt + 0x3C].copy_from_slice(&0x27000u32.to_le_bytes());
        bytes[opt + 0x3C..opt + 0x40].copy_from_slice(&0x600u32.to_le_bytes());
        bytes[opt + 0x44..opt + 0x46].copy_from_slice(&3u16.to_le_bytes());
        bytes[opt + 0x46..opt + 0x48].copy_from_slice(&0x160u16.to_le_bytes());
        bytes[opt + 0x6C..opt + 0x70].copy_from_slice(&16u32.to_le_bytes());

        let dd = opt + 0x70;
        bytes[dd + 8..dd + 12].copy_from_slice(&0x9000u32.to_le_bytes());
        bytes[dd + 12..dd + 16].copy_from_slice(&0x908u32.to_le_bytes());
        bytes[dd + 3 * 8..dd + 3 * 8 + 4].copy_from_slice(&0x6000u32.to_le_bytes());
        bytes[dd + 3 * 8 + 4..dd + 3 * 8 + 8].copy_from_slice(&0x234u32.to_le_bytes());
        bytes[dd + 12 * 8..dd + 12 * 8 + 4].copy_from_slice(&0x9280u32.to_le_bytes());
        bytes[dd + 12 * 8 + 4..dd + 12 * 8 + 8].copy_from_slice(&0x1B8u32.to_le_bytes());

        bytes
    }

    #[test]
    fn parses_minimal_pe() {
        let bytes = minimal_pe();
        let headers = parse(&bytes).expect("PE mínimo válido");
        assert_eq!(headers.e_lfanew, 0x80);
        assert_eq!(headers.machine, 0x8664);
        assert_eq!(headers.number_of_sections, 8);
        assert_eq!(headers.time_date_stamp, 0xD483ACA1);
        assert_eq!(headers.size_of_optional_header, 0x00F0);
        assert_eq!(headers.characteristics, 0x0022);
        assert_eq!(headers.optional.magic, OPTIONAL_MAGIC_PE32_PLUS);
        assert_eq!(headers.optional.address_of_entry_point, 0x1440);
        assert_eq!(headers.optional.image_base, 0x1_4000_0000);
        assert_eq!(headers.optional.number_of_rva_and_sizes, 16);
        assert_eq!(headers.optional.data_directory_offset, 0x108);
        assert_eq!(headers.optional.data_directories.len(), 16);
        assert!(headers.optional.data_directories[0].is_empty());
        assert_eq!(headers.optional.data_directories[1].rva, 0x9000);
        assert_eq!(headers.optional.data_directories[1].size, 0x908);
        assert_eq!(headers.optional.data_directories[3].rva, 0x6000);
        assert_eq!(headers.optional.data_directories[12].rva, 0x9280);
    }

    #[test]
    fn rejects_non_pe() {
        let err = parse(b"not a pe file").unwrap_err();
        assert!(matches!(err, Error::TooShort { .. }));
    }

    #[test]
    fn rejects_bad_optional_magic() {
        let mut bytes = minimal_pe();
        bytes[0x98..0x9A].copy_from_slice(&0x1234u16.to_le_bytes());
        let err = parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::BadOptionalMagic(0x1234)));
    }

    #[test]
    fn rejects_truncated_optional_header() {
        let mut bytes = minimal_pe();
        bytes.truncate(0x100);
        let err = parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::TooShort { .. }));
    }

    #[test]
    fn respects_number_of_rva_and_sizes() {
        let mut bytes = minimal_pe();
        bytes[0x98 + 0x6C..0x98 + 0x70].copy_from_slice(&2u32.to_le_bytes());
        let headers = parse(&bytes).expect("PE mínimo válido");
        assert_eq!(headers.optional.data_directories.len(), 2);
    }

    #[test]
    fn caps_data_directories_at_sixteen() {
        let mut bytes = minimal_pe();
        bytes[0x98 + 0x6C..0x98 + 0x70].copy_from_slice(&32u32.to_le_bytes());
        let headers = parse(&bytes).expect("PE mínimo válido");
        assert_eq!(headers.optional.data_directories.len(), 16);
    }
}
