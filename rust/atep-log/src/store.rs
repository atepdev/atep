//! Append-only record file. Each record is `u32 length (big endian) || payload
//! || first 8 bytes of SHA-256(payload)`; the file starts with an 8 byte magic.
//! An append is a single write followed by `fsync`, so a crash leaves at most
//! one torn record at the end, which `open` detects and truncates. A damaged
//! record that is followed by more data is corruption and is an error.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use atep_core::keys::sha256;

use crate::LogError;

const MAGIC: &[u8; 8] = b"ATEPLOG1";
const MAX_RECORD: usize = 16 * 1024 * 1024;

pub struct RecordFile {
    file: File,
    path: PathBuf,
    len: u64,
}

/// One record read at open time: its payload offset in the file and the payload.
pub struct Loaded {
    pub offset: u64,
    pub payload: Vec<u8>,
}

fn io_err(path: &Path, e: io::Error) -> LogError {
    LogError::Io(format!("{}: {e}", path.display()))
}

impl RecordFile {
    /// Open or create the file and read every record. Returns the loaded
    /// records and the number of torn tail bytes that were cut off.
    pub fn open(path: &Path) -> Result<(RecordFile, Vec<Loaded>, u64), LogError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| io_err(path, e))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| io_err(path, e))?;
        let mut rf = RecordFile {
            file,
            path: path.to_path_buf(),
            len: data.len() as u64,
        };
        if data.is_empty() {
            rf.write_raw(MAGIC)?;
            return Ok((rf, Vec::new(), 0));
        }
        if data.len() < MAGIC.len() {
            // A crash while creating the file.
            rf.truncate(0)?;
            rf.write_raw(MAGIC)?;
            return Ok((rf, Vec::new(), data.len() as u64));
        }
        if &data[..8] != MAGIC {
            return Err(LogError::Corrupt(format!(
                "{}: bad magic, not an ATEP log file",
                path.display()
            )));
        }
        let (records, good_end) = parse(&data, path)?;
        let torn = data.len() as u64 - good_end;
        if torn > 0 {
            rf.truncate(good_end)?;
        }
        Ok((rf, records, torn))
    }

    /// Read every record without modifying the file (monitors, tools).
    pub fn read_all(path: &Path) -> Result<Vec<Loaded>, LogError> {
        let data = std::fs::read(path).map_err(|e| io_err(path, e))?;
        if data.len() < MAGIC.len() {
            return Ok(Vec::new());
        }
        if &data[..8] != MAGIC {
            return Err(LogError::Corrupt(format!(
                "{}: bad magic, not an ATEP log file",
                path.display()
            )));
        }
        Ok(parse(&data, path)?.0)
    }

    fn write_raw(&mut self, bytes: &[u8]) -> Result<(), LogError> {
        self.file
            .write_all_at(bytes, self.len)
            .map_err(|e| io_err(&self.path, e))?;
        self.file.sync_data().map_err(|e| io_err(&self.path, e))?;
        self.len += bytes.len() as u64;
        Ok(())
    }

    fn truncate(&mut self, len: u64) -> Result<(), LogError> {
        self.file.set_len(len).map_err(|e| io_err(&self.path, e))?;
        self.file.sync_all().map_err(|e| io_err(&self.path, e))?;
        self.len = len;
        Ok(())
    }

    /// Append one record durably and return the offset of its payload.
    pub fn append(&mut self, payload: &[u8]) -> Result<u64, LogError> {
        if payload.len() > MAX_RECORD {
            return Err(LogError::Io("record too large".into()));
        }
        let mut buf = Vec::with_capacity(payload.len() + 12);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&sha256(payload)[..8]);
        let offset = self.len + 4;
        self.write_raw(&buf)?;
        Ok(offset)
    }

    /// Read the payload of the record whose payload starts at `offset`.
    pub fn read_at(&self, offset: u64) -> Result<Vec<u8>, LogError> {
        let mut head = [0u8; 4];
        self.file
            .read_exact_at(&mut head, offset - 4)
            .map_err(|e| io_err(&self.path, e))?;
        let n = u32::from_be_bytes(head) as usize;
        let mut buf = vec![0u8; n + 8];
        self.file
            .read_exact_at(&mut buf, offset)
            .map_err(|e| io_err(&self.path, e))?;
        if sha256(&buf[..n])[..8] != buf[n..] {
            return Err(LogError::Corrupt(format!(
                "{}: record at {offset} fails its checksum",
                self.path.display()
            )));
        }
        buf.truncate(n);
        Ok(buf)
    }
}

fn parse(data: &[u8], path: &Path) -> Result<(Vec<Loaded>, u64), LogError> {
    let mut pos = MAGIC.len();
    let mut out = Vec::new();
    while pos < data.len() {
        let rest = &data[pos..];
        if rest.len() < 4 {
            break;
        }
        let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        if n > MAX_RECORD || rest.len() < 4 + n + 8 {
            // Incomplete record: only acceptable as the final, torn one.
            if n > MAX_RECORD && rest.len() >= 4 + 8 {
                return Err(LogError::Corrupt(format!(
                    "{}: record at byte {pos} has an impossible length",
                    path.display()
                )));
            }
            break;
        }
        let payload = &rest[4..4 + n];
        let check = &rest[4 + n..4 + n + 8];
        if sha256(payload)[..8] != *check {
            if pos + 4 + n + 8 == data.len() {
                break; // damaged last record: a torn write
            }
            return Err(LogError::Corrupt(format!(
                "{}: record at byte {pos} fails its checksum and is followed by more data",
                path.display()
            )));
        }
        out.push(Loaded {
            offset: (pos + 4) as u64,
            payload: payload.to_vec(),
        });
        pos += 4 + n + 8;
    }
    Ok((out, pos as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("atep-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("f.rec")
    }

    #[test]
    fn append_reload_and_torn_tail() {
        let p = tmp("torn");
        let (mut f, recs, torn) = RecordFile::open(&p).unwrap();
        assert!(recs.is_empty() && torn == 0);
        let o1 = f.append(b"one").unwrap();
        f.append(b"two two").unwrap();
        assert_eq!(f.read_at(o1).unwrap(), b"one");
        drop(f);
        // Simulate a crash in the middle of the third append.
        let mut data = std::fs::read(&p).unwrap();
        let good = data.len();
        data.extend_from_slice(&[0, 0, 0, 9, b'p', b'a', b'r']);
        std::fs::write(&p, &data).unwrap();
        let (mut f, recs, torn) = RecordFile::open(&p).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(torn, 7);
        assert_eq!(std::fs::metadata(&p).unwrap().len() as usize, good);
        f.append(b"three").unwrap();
        drop(f);
        let (_, recs, torn) = RecordFile::open(&p).unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(torn, 0);
        assert_eq!(recs[2].payload, b"three");
    }

    #[test]
    fn damaged_middle_record_is_corruption() {
        let p = tmp("mid");
        let (mut f, _, _) = RecordFile::open(&p).unwrap();
        f.append(b"first").unwrap();
        f.append(b"second").unwrap();
        drop(f);
        let mut data = std::fs::read(&p).unwrap();
        data[8 + 4] ^= 1; // first payload byte
        std::fs::write(&p, &data).unwrap();
        assert!(matches!(RecordFile::open(&p), Err(LogError::Corrupt(_))));
    }
}
