mod fixtures;
use evtx::EvtxParser;
use fixtures::*;

const CHUNK_START: usize = 0x1000;
const CHUNK_SIZE: usize = 0x10000;

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Offsets of the allocated records in a chunk, walked by record size.
fn record_offsets(chunk: &[u8]) -> Vec<usize> {
    let free_space = read_u32(chunk, 48) as usize;
    let mut offsets = vec![];
    let mut offset = 512;
    while offset < free_space {
        offsets.push(offset);
        offset += read_u32(chunk, offset + 4) as usize;
    }
    offsets
}

/// Recompute the event records checksum after the records were changed.
fn fix_records_checksum(chunk: &mut [u8]) {
    let free_space = read_u32(chunk, 48) as usize;
    let checksum = crc32fast::hash(&chunk[512..free_space]);
    chunk[52..56].copy_from_slice(&checksum.to_le_bytes());
}

/// Recompute the header checksum after the header was changed.
fn fix_header_checksum(chunk: &mut [u8]) {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&chunk[..120]);
    hasher.update(&chunk[128..512]);
    let checksum = hasher.finalize();
    chunk[124..128].copy_from_slice(&checksum.to_le_bytes());
}

fn count_records(data: Vec<u8>) -> (usize, usize) {
    let mut parser = EvtxParser::from_buffer(data).unwrap();
    let (mut ok, mut errors) = (0, 0);
    for record in parser.records() {
        match record {
            Ok(_) => ok += 1,
            Err(_) => errors += 1,
        }
    }
    (ok, errors)
}

fn sample() -> Vec<u8> {
    std::fs::read(regular_sample()).unwrap()
}

#[test]
fn test_earlier_record_with_the_last_record_id_does_not_end_the_chunk() {
    ensure_env_logger_initialized();
    let expected = count_records(sample());
    assert_eq!(expected, (2261, 0));

    // Real Windows chunks can hold an earlier record with the same ID as the header's last
    // record ID. Give the third record of the first chunk that ID.
    let mut data = sample();
    let chunk = &mut data[CHUNK_START..CHUNK_START + CHUNK_SIZE];
    let offsets = record_offsets(chunk);
    assert_eq!(offsets.len(), 91);
    let last_record_id = read_u64(chunk, 32);
    chunk[offsets[2] + 8..offsets[2] + 16].copy_from_slice(&last_record_id.to_le_bytes());
    fix_records_checksum(chunk);

    assert_eq!(count_records(data), expected);
}

#[test]
fn test_walk_stops_after_the_last_record_when_free_space_starts_later() {
    ensure_env_logger_initialized();
    // Some producers write a free space offset past the last record. The walk must still end
    // at the header's last record offset instead of reading the slack after it as a record.
    // The third chunk has room for that and stale bytes in its slack.
    let mut data = sample();
    let start = CHUNK_START + 2 * CHUNK_SIZE;
    let chunk = &mut data[start..start + CHUNK_SIZE];
    let free_space = read_u32(chunk, 48) as usize;
    let extended = free_space + 256;
    assert!(extended <= CHUNK_SIZE);
    chunk[48..52].copy_from_slice(&(extended as u32).to_le_bytes());
    fix_records_checksum(chunk);
    fix_header_checksum(chunk);

    assert_eq!(count_records(data), (2261, 0));
}

#[test]
fn record_start_past_a_misaligned_last_offset_is_not_allocated() {
    let mut data = sample();
    let chunk = &mut data[CHUNK_START..CHUNK_START + CHUNK_SIZE];
    let offsets = record_offsets(chunk);
    let boundary = (offsets[offsets.len() - 2] + 8) as u32;
    chunk[44..48].copy_from_slice(&boundary.to_le_bytes());
    fix_header_checksum(chunk);
    assert_eq!(count_records(data), (2260, 0));
}

#[test]
fn missing_last_offset_uses_free_space_even_when_an_id_repeats() {
    let mut data = sample();
    let chunk = &mut data[CHUNK_START..CHUNK_START + CHUNK_SIZE];
    let offsets = record_offsets(chunk);
    let last_id = read_u64(chunk, 32);
    chunk[offsets[2] + 8..offsets[2] + 16].copy_from_slice(&last_id.to_le_bytes());
    chunk[44..48].copy_from_slice(&0u32.to_le_bytes());
    fix_records_checksum(chunk);
    fix_header_checksum(chunk);
    assert_eq!(count_records(data), (2261, 0));
}

#[test]
fn invalid_free_space_offset_fails_checksum_validation() {
    let data = sample();
    let mut chunk =
        evtx::EvtxChunkData::new(data[CHUNK_START..CHUNK_START + CHUNK_SIZE].to_vec(), true)
            .unwrap();
    for invalid in [0, u32::MAX] {
        chunk.header.free_space_offset = invalid;
        assert!(!chunk.validate_data_checksum());
    }
}
