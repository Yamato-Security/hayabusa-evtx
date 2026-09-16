use crate::err::DeserializationResult as Result;

use crate::ChunkOffset;
pub use byteorder::{LittleEndian, ReadBytesExt};

use crate::utils::read_len_prefixed_utf16_string;

use std::{
    fmt::Formatter,
    io::{self, Cursor, Seek, SeekFrom},
};

use quick_xml::events::{BytesEnd, BytesStart};
use std::fmt;

#[derive(Debug, PartialEq, Eq, PartialOrd, Clone, Hash)]
pub struct BinXmlName {
    str: String,
}

#[derive(Debug, PartialOrd, PartialEq, Eq, Clone, Hash)]
pub struct BinXmlNameRef {
    pub offset: ChunkOffset,
}

impl fmt::Display for BinXmlName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.str)
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub(crate) struct BinXmlNameLink {
    pub next_string: Option<ChunkOffset>,
    pub hash: u16,
}

impl BinXmlNameLink {
    pub fn from_stream(stream: &mut Cursor<&[u8]>) -> Result<Self> {
        let next_string = try_read!(stream, u32)?;
        let name_hash = try_read!(stream, u16, "name_hash")?;

        Ok(BinXmlNameLink {
            next_string: if next_string > 0 {
                Some(next_string)
            } else {
                None
            },
            hash: name_hash,
        })
    }

    pub fn data_size() -> u32 {
        6
    }
}

impl BinXmlNameRef {
    pub fn from_stream(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let name_offset = try_read!(cursor, u32, "name_offset")?;

        let position_before_string = cursor.position();
        let need_to_seek = position_before_string == u64::from(name_offset);

        if need_to_seek {
            let _ = BinXmlNameLink::from_stream(cursor)?;
            let len = cursor.read_u16::<LittleEndian>()?;

            let nul_terminator_len = 4;
            let data_size = BinXmlNameLink::data_size() + u32::from(len) * 2 + nul_terminator_len;
            let end_position = position_before_string + u64::from(data_size);

            // Cursor::seek permits positions past the buffer, so check the complete
            // name (including its terminator) before skipping it.
            if end_position > cursor.get_ref().len() as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "inline BinXML name exceeds the input buffer",
                )
                .into());
            }

            try_seek!(cursor, end_position, "Skip string")?;
        }

        Ok(BinXmlNameRef {
            offset: name_offset,
        })
    }
}

impl BinXmlName {
    #[cfg(test)]
    pub(crate) fn from_str(s: &str) -> Self {
        BinXmlName { str: s.to_string() }
    }

    #[cfg(test)]
    pub(crate) fn from_string(s: String) -> Self {
        BinXmlName { str: s }
    }

    /// Reads a tuple of (String, Hash, Offset) from a stream.
    pub fn from_stream(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let name =
            try_read!(cursor, len_prefixed_utf_16_str_nul_terminated, "name")?.unwrap_or_default();

        Ok(BinXmlName { str: name })
    }

    pub fn as_str(&self) -> &str {
        &self.str
    }
}

impl<'a> From<&'a BinXmlName> for quick_xml::events::BytesStart<'a> {
    fn from(name: &'a BinXmlName) -> Self {
        BytesStart::new(name.as_str())
    }
}

impl<'a> From<&'a BinXmlName> for quick_xml::events::BytesEnd<'a> {
    fn from(name: &'a BinXmlName) -> Self {
        BytesEnd::new(name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::err::DeserializationError;
    use std::io::ErrorKind;

    fn name_data(len: u16) -> Vec<u8> {
        let mut data = len.to_le_bytes().to_vec();
        for _ in 0..len {
            data.extend_from_slice(&[b'A', 0]);
        }
        data.extend_from_slice(&[0, 0]);
        data
    }

    fn inline_name_data(len: u16) -> Vec<u8> {
        let mut data = 4_u32.to_le_bytes().to_vec();
        // Next-string offset and name hash.
        data.extend_from_slice(&[0; 6]);
        data.extend_from_slice(&name_data(len));
        data
    }

    #[test]
    fn test_inline_name_length_boundaries() {
        for len in [0, 1, 32767, 32768, u16::MAX] {
            let data = inline_name_data(len);
            let mut cursor = Cursor::new(data.as_slice());
            let name_ref = BinXmlNameRef::from_stream(&mut cursor).unwrap();
            assert_eq!(name_ref.offset, 4);
            assert_eq!(cursor.position(), data.len() as u64, "length {len}");
        }
    }

    #[test]
    fn test_truncated_inline_name_returns_error() {
        for len in [0, 1, 32767, 32768, u16::MAX] {
            let data = inline_name_data(len);
            // A missing terminator byte must not be skipped past the input either.
            for available in [12, data.len() - 1] {
                let mut cursor = Cursor::new(&data[..available]);
                let error = BinXmlNameRef::from_stream(&mut cursor).unwrap_err();
                assert!(matches!(
                    error,
                    DeserializationError::RemoveMe(ref io) if io.kind() == ErrorKind::UnexpectedEof
                ));
                assert_eq!(cursor.position(), 12);
            }
        }
    }

    #[test]
    fn test_out_of_line_name_does_not_skip_input() {
        let data = 0_u32.to_le_bytes();
        let mut cursor = Cursor::new(data.as_slice());
        let name_ref = BinXmlNameRef::from_stream(&mut cursor).unwrap();
        assert_eq!(name_ref.offset, 0);
        assert_eq!(cursor.position(), 4);
    }

    #[test]
    fn test_cached_name_length_boundaries() {
        for len in [0, 1, 32767, 32768, u16::MAX] {
            let data = name_data(len);
            let mut cursor = Cursor::new(data.as_slice());
            let name = BinXmlName::from_stream(&mut cursor).unwrap();
            assert_eq!(name.as_str(), "A".repeat(usize::from(len)));
            assert_eq!(cursor.position(), data.len() as u64, "length {len}");
        }
    }

    #[test]
    fn test_truncated_large_cached_name_returns_error() {
        let data = [0, 0x80, 0, 0]; // Length 32768, but only one UTF-16 code unit.
        let mut cursor = Cursor::new(data.as_slice());
        assert!(BinXmlName::from_stream(&mut cursor).is_err());
    }
}
