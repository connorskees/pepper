
struct DosHeader {
    /// ID signature ('MZ' or 'ZM')
    /// 
    /// Some older compilers were little-endian ignorant
    signature: [u8; 2],
    /// Image size mod 512
    lastsize: u16,
    /// Number of 512-byte pages in image
    /// Size of total file = `nblocks` * 512 + `lastsize`
    nblocks: u16,
    /// count of relocation table entries
    nreloc: u16,
    /// size of header, in paragraphs
    hdrsize: u16,
    /// min required mem
    minalloc: u16,
    /// max required mem
    maxalloc: u16,
    /// stack seg offset in load module
    ss: u16,
    /// initial value of sp
    sp: u16,
    /// file checksum
    /// 
    /// one's complement of the sum of all words in .exe file
    /// (checksum is assumed 00h when reading file for calculation)
    /// If checksum is zero, no checksum is used
    checksum: u16,
    /// initial value of IP
    ip: u16,
    /// cs offset in load module
    cs: u16,
    /// offset of first reloc item
    /// (Usually set to 0x1E for MS, 0x1C for Borland)
    relocpos: u16,
    /// overlay number
    /// (most of the time is zero)
    noverlay: u16,
    /// relocation items usually start here (unless MS, then 0x1E)
    reserved1: [u16; 4],
    oem_id: u16,
    oem_info: u16,
    reserved2: [u16; 10],
    /// Offset to the 'PE\0\0' signature relative to the beginning of the file
    e_lfanew: u32, 
}
