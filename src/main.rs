#![feature(bufreader_seek_relative)]
#![allow(dead_code, unused_imports)]

use std::{
    convert::TryFrom,
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

use utils::read_u32;

const DOS_HEADER: [u8; 60] = [0_u8; 60];
const PE_HEADER: &[u8; 4] = b"PE\0\0";

mod coff;
mod dos;
mod utils;

type PEResult<T> = Result<T, PEError>;

#[derive(Debug)]
enum PEError {
    IoError(io::Error),
    InvalidMachineType(u16),
}

impl From<io::Error> for PEError {
    fn from(err: io::Error) -> Self {
        PEError::IoError(err)
    }
}

#[derive(Debug)]
struct PortableExecutable {}

/// The machine field has one of the following values that specifies its CPU type.
///
/// An image file can be run only on the specified machine or on a system that emulates the specified machine.
#[derive(Debug)]
#[repr(u16)]
enum Machine {
    /// The contents of this field are assumed to be applicable to any machine type
    Unknown = 0x0,
    /// Matsushita AM33
    Am33 = 0x1d3,
    /// x64
    Amd64 = 0x8664,
    /// ARM little endian
    Arm = 0x1c0,
    /// ARM64 little endian
    Arm64 = 0xaa64,
    /// ARM Thumb-2 little endian
    Armnt = 0x1c4,
    /// EFI byte code
    Ebc = 0xebc,
    /// Intel 386 or later processors and compatible processors
    I386 = 0x14c,
    /// Intel Itanium processor family
    Ia64 = 0x200,
    /// Mitsubishi M32R little endian
    M32R = 0x9041,
    /// MIPS16
    Mips16 = 0x266,
    /// MIPS with FPU
    MipsFpu = 0x366,
    /// MIPS16 with FPU
    MipsFpu16 = 0x466,
    /// Power PC little endian
    PowerPc = 0x1f0,
    /// Power PC with floating point support
    PowerPcFp = 0x1f1,
    /// MIPS little endian
    R4000 = 0x166,
    /// RISC-V 32-bit address space
    RiscV32 = 0x5032,
    /// RISC-V 64-bit address space
    RiscV64 = 0x5064,
    /// RISC-V 128-bit address space
    RiscV128 = 0x5128,
    /// Hitachi SH3
    Sh3 = 0x1a2,
    /// Hitachi SH3 DSP
    Sh3Dsp = 0x1a3,
    /// Hitachi SH4
    Sh4 = 0x1a6,
    /// Hitachi SH5
    Sh5 = 0x1a8,
    /// Thumb
    Thumb = 0x1c2,
    /// MIPS little-endian WCE v2
    WceMipsV2 = 0x169,
}

impl TryFrom<u16> for Machine {
    type Error = PEError;
    fn try_from(n: u16) -> PEResult<Machine> {
        match n {
            0x0 => Ok(Machine::Unknown),
            0x1d3 => Ok(Machine::Am33),
            0x8664 => Ok(Machine::Amd64),
            0x1c0 => Ok(Machine::Arm),
            0xaa64 => Ok(Machine::Arm64),
            0x1c4 => Ok(Machine::Armnt),
            0xebc => Ok(Machine::Ebc),
            0x14c => Ok(Machine::I386),
            0x200 => Ok(Machine::Ia64),
            0x9041 => Ok(Machine::M32R),
            0x266 => Ok(Machine::Mips16),
            0x366 => Ok(Machine::MipsFpu),
            0x466 => Ok(Machine::MipsFpu16),
            0x1f0 => Ok(Machine::PowerPc),
            0x1f1 => Ok(Machine::PowerPcFp),
            0x166 => Ok(Machine::R4000),
            0x5032 => Ok(Machine::RiscV32),
            0x5064 => Ok(Machine::RiscV64),
            0x5128 => Ok(Machine::RiscV128),
            0x1a2 => Ok(Machine::Sh3),
            0x1a3 => Ok(Machine::Sh3Dsp),
            0x1a6 => Ok(Machine::Sh4),
            0x1a8 => Ok(Machine::Sh5),
            0x1c2 => Ok(Machine::Thumb),
            0x169 => Ok(Machine::WceMipsV2),
            _ => Err(PEError::InvalidMachineType(n)),
        }
    }
}

enum Characteristics {
    /// Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
    RelocsStripped = 0x0001,
    /// Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
    ExecutableImage = 0x0002,
    /// COFF line numbers have been removed. This flag is deprecated and should be zero.
    LineNumsStripped = 0x0004,
    /// COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
    LocalSymsStripped = 0x0008,
    /// Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
    AggressiveWsTrim = 0x0010,
    /// Application can handle > 2-GB addresses.
    LargeAddressAware = 0x0020,
    /// This flag is reserved for future use.
    Reserved = 0x0040,
    /// Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
    BytesReversedLo = 0x0080,
    /// Machine is based on a 32-bit-word architecture.
    Machine32Bit = 0x0100,
    /// Debugging information is removed from the image file.
    DebugStripped = 0x0200,
    /// If the image is on removable media, fully load it and copy it to the swap file.
    RemovableRunFromSwap = 0x0400,
    /// If the image is on network media, fully load it and copy it to the swap file.
    NetRunFromSwap = 0x0800,
    /// The image file is a system file, not a user program.
    System = 0x1000,
    /// The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
    Dll = 0x2000,
    /// The file should be run only on a uniprocessor machine.
    UpSystemOnly = 0x4000,
    /// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    BytesReversedHi = 0x8000,
}

struct Parser {}

impl Parser {
    fn parse_pe<P: AsRef<Path>>(path: P) -> PEResult<PortableExecutable> {
        let mut buf = BufReader::new(File::open(path)?);

        buf.read_exact(&mut DOS_HEADER)?;

        let ptr = read_u32(&mut buf)?;

        dbg!(ptr);
        buf.seek_relative(i64::from(ptr) - 64)?;
        assert_eq!(&read_bytes_to_buffer!(buf, 4), PE_HEADER);

        Ok(PortableExecutable {})
    }
}

fn main() -> io::Result<()> {
    let pe = Parser::parse_pe("pepper.exe");

    dbg!(pe).unwrap();

    Ok(())
}
