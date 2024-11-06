pub const MEMLOCK_128M: u64 = 128 << 20;

pub const POLL_PER_MINISECOND: u64 = 200;

use pcap_file::Endianness;
pub const ENDIANNESS: Endianness = Endianness::Big;
// We can handle only version 1.0
pub const MAJOR_VERSION: u16 = 1;
pub const MINOR_VERSION: u16 = 0;
pub const SECTION_LENGTH_DEFAULT: i64 = -1;