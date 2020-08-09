use std::io::{self, Read};

pub(crate) fn read_u8(buf: &mut dyn Read) -> io::Result<u8> {
    let mut buffer = [0_u8];
    buf.read_exact(&mut buffer)?;
    Ok(u8::from_le_bytes(buffer))
}

/// Read 2 bytes as a u16
pub(crate) fn read_u16(buf: &mut dyn Read) -> io::Result<u16> {
    let mut buffer = [0_u8; 2];
    buf.read_exact(&mut buffer)?;
    Ok(u16::from_le_bytes(buffer))
}

/// Read 4 bytes as a u32
pub(crate) fn read_u32(buf: &mut dyn Read) -> io::Result<u32> {
    let mut buffer = [0_u8; 4];
    buf.read_exact(&mut buffer)?;
    Ok(u32::from_le_bytes(buffer))
}

/// Read `n` bytes as [u8; n]
/// This is a hack until const generics
#[macro_export]
macro_rules! read_bytes_to_buffer {
    ($reader:expr, $bytes:literal) => {
        if let Some(mut buffer) = Some([0_u8; $bytes]) {
            $reader.read_exact(&mut buffer)?;
            buffer
        } else {
            unreachable!()
        }
    };
}