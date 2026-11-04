use std::env;
use std::fmt;
use std::fs;
use std::process::ExitCode;

const DOS_HEADER_MIN: usize = 64;
const E_LFANEW_OFFSET: usize = 0x3C;
const PE_SIGNATURE: u32 = 0x0000_4550;
const COFF_SIZE: usize = 20;

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

    Ok(Headers {
        e_lfanew,
        machine: read_u16(bytes, coff)?,
        number_of_sections: read_u16(bytes, coff + 2)?,
        time_date_stamp: read_u32(bytes, coff + 4)?,
        pointer_to_symbol_table: read_u32(bytes, coff + 8)?,
        number_of_symbols: read_u32(bytes, coff + 12)?,
        size_of_optional_header: read_u16(bytes, coff + 16)?,
        characteristics: read_u16(bytes, coff + 18)?,
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
    println!("Optional header en 0x{optional:08X} (pendiente: miércoles)");
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
    }

    #[test]
    fn rejects_non_pe() {
        let err = parse(b"not a pe file").unwrap_err();
        assert!(matches!(err, Error::TooShort { .. }));
    }
}
