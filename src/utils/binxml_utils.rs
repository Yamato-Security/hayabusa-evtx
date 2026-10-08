use crate::AnsiCodec;
use crate::evtx_parser::ReadSeek;
use thiserror::Error;

use crate::err::{DeserializationError, DeserializationResult};

use byteorder::{LittleEndian, ReadBytesExt};

use log::trace;
use std::char::decode_utf16;
use std::io::{self, Error, ErrorKind};

#[derive(Debug, Error)]
pub enum FailedToReadString {
    #[error("An I/O error has occurred")]
    IoError(#[from] io::Error),
}

pub fn read_len_prefixed_utf16_string<T: ReadSeek>(
    stream: &mut T,
    is_null_terminated: bool,
) -> Result<Option<String>, FailedToReadString> {
    let expected_number_of_characters = stream.read_u16::<LittleEndian>()?;
    let needed_bytes = u64::from(expected_number_of_characters) * 2;

    trace!(
        "Offset `0x{offset:08x} ({offset})` reading a{nul}string of len {len}",
        offset = stream.tell().unwrap_or(0),
        nul = if is_null_terminated {
            " null terminated "
        } else {
            " "
        },
        len = expected_number_of_characters
    );

    let s = read_utf16_by_size(stream, needed_bytes)?;

    if is_null_terminated {
        stream.read_u16::<LittleEndian>()?;
    };

    // It is useless to check for size equality, since u16 characters may be decoded into multiple u8 chars,
    // so we might end up with more characters than originally asked for.
    //
    // Moreover, the code will also not read **less** characters than asked.
    Ok(s)
}

/// Reads a utf16 string from the given stream.
/// size is the actual byte representation of the string (not the number of characters).
pub fn read_utf16_by_size<T: ReadSeek>(stream: &mut T, size: u64) -> io::Result<Option<String>> {
    match size {
        0 => Ok(None),
        _ => read_utf16_string(stream, Some(size as usize / 2)).map(|mut s| {
            // Strip nul terminator if needed
            if let Some('\0') = s.chars().last() {
                s.pop();
            }
            Some(s)
        }),
    }
}

/// Reads an ansi encoded string from the given stream using `ansi_codec`.
pub fn read_ansi_encoded_string<T: ReadSeek>(
    stream: &mut T,
    size: u64,
    ansi_codec: AnsiCodec,
) -> DeserializationResult<Option<String>> {
    match size {
        0 => Ok(None),
        _ => {
            let mut bytes = vec![0; size as usize];
            stream.read_exact(&mut bytes)?;

            // There may be multiple NULs in the string, prune them.
            bytes.retain(|&b| b != 0);

            // A leading BOM stays data, and invalid sequences error instead of
            // becoming U+FFFD.
            let decoded = ansi_codec
                .decode_without_bom_handling_and_without_replacement(&bytes)
                .ok_or_else(|| DeserializationError::AnsiDecodeError {
                    encoding_used: ansi_codec.name(),
                    inner_message: "invalid sequence".to_owned(),
                })?;

            Ok(Some(decoded.into_owned()))
        }
    }
}

pub fn read_null_terminated_utf16_string<T: ReadSeek>(stream: &mut T) -> io::Result<String> {
    read_utf16_string(stream, None)
}

/// Reads a utf16 string from the given stream.
/// If `len` is given, exactly `len` u16 values are read from the stream.
/// If `len` is None, the string is assumed to be null terminated and the stream will be read to the first null (0).
fn read_utf16_string<T: ReadSeek>(stream: &mut T, len: Option<usize>) -> io::Result<String> {
    let mut buffer = match len {
        Some(len) => Vec::with_capacity(len),
        None => Vec::new(),
    };

    match len {
        Some(len) => {
            for _ in 0..len {
                let next_char = stream.read_u16::<byteorder::LittleEndian>()?;
                buffer.push(next_char);
            }
        }
        None => loop {
            let next_char = stream.read_u16::<byteorder::LittleEndian>()?;

            if next_char == 0 {
                break;
            }

            buffer.push(next_char);
        },
    }

    // We need to stop if we see a NUL byte, even if asked for more bytes.
    decode_utf16(buffer.into_iter().take_while(|&byte| byte != 0x00))
        .map(|r| r.map_err(|_e| Error::from(ErrorKind::InvalidData)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_ansi_windows_1255_decodes_0xca_as_u05ba() {
        // Byte 0xCA was unassigned in the old `encoding` crate (strict decode
        // errored); the Encoding Standard maps it to U+05BA.
        let mut cursor = Cursor::new(&[0xCAu8][..]);
        let decoded = read_ansi_encoded_string(&mut cursor, 1, encoding_rs::WINDOWS_1255)
            .expect("windows-1255 must accept 0xCA")
            .expect("non-empty input");
        assert_eq!(decoded, "\u{05BA}");
    }
}
