//! Minimal CBOR value model with RFC 8949 section 4.2 deterministic encoding
//! and a strict decoder that rejects anything that is not deterministic.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CborError(pub String);

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cbor: {}", self.0)
    }
}

impl std::error::Error for CborError {}

fn err<T>(msg: &str) -> Result<T, CborError> {
    Err(CborError(msg.to_string()))
}

const MAX_DEPTH: usize = 32;

impl Value {
    pub fn bytes(b: &[u8]) -> Value {
        Value::Bytes(b.to_vec())
    }

    pub fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Look up an integer-keyed entry in a map.
    pub fn map_get_int(&self, key: i64) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| *k == Value::Int(key))
            .map(|(_, v)| v)
    }

    /// Deterministic encoding (RFC 8949 section 4.2.1): shortest-form heads,
    /// definite lengths, map keys sorted by the bytewise order of their encodings.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Value::Int(i) => {
                if *i >= 0 {
                    head(out, 0, *i as u64);
                } else {
                    head(out, 1, (-1 - *i) as u64);
                }
            }
            Value::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(a) => {
                head(out, 4, a.len() as u64);
                for v in a {
                    v.encode_into(out);
                }
            }
            Value::Map(m) => {
                let mut entries: Vec<(Vec<u8>, Vec<u8>)> =
                    m.iter().map(|(k, v)| (k.encode(), v.encode())).collect();
                entries.sort_by(|a, b| a.0.cmp(&b.0));
                head(out, 5, entries.len() as u64);
                for (k, v) in entries {
                    out.extend_from_slice(&k);
                    out.extend_from_slice(&v);
                }
            }
            Value::Tag(t, v) => {
                head(out, 6, *t);
                v.encode_into(out);
            }
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Null => out.push(0xf6),
        }
    }

    /// Strict decode of exactly one item. Rejects trailing bytes, indefinite
    /// lengths, non-shortest heads, unsorted or duplicate map keys, floats and
    /// undefined or unassigned simple values.
    pub fn decode(data: &[u8]) -> Result<Value, CborError> {
        let mut pos = 0usize;
        let v = decode_item(data, &mut pos, 0)?;
        if pos != data.len() {
            return err("trailing bytes after item");
        }
        Ok(v)
    }
}

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn take<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], CborError> {
    if data.len() - *pos < n {
        return err("unexpected end of input");
    }
    let s = &data[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

fn read_arg(data: &[u8], pos: &mut usize, info: u8) -> Result<u64, CborError> {
    match info {
        0..=23 => Ok(info as u64),
        24 => {
            let v = take(data, pos, 1)?[0] as u64;
            if v < 24 {
                return err("non-shortest integer encoding");
            }
            Ok(v)
        }
        25 => {
            let b = take(data, pos, 2)?;
            let v = u16::from_be_bytes([b[0], b[1]]) as u64;
            if v <= 0xff {
                return err("non-shortest integer encoding");
            }
            Ok(v)
        }
        26 => {
            let b = take(data, pos, 4)?;
            let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
            if v <= 0xffff {
                return err("non-shortest integer encoding");
            }
            Ok(v)
        }
        27 => {
            let b = take(data, pos, 8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            let v = u64::from_be_bytes(a);
            if v <= 0xffff_ffff {
                return err("non-shortest integer encoding");
            }
            Ok(v)
        }
        28..=30 => err("reserved additional information"),
        _ => err("indefinite length not allowed"),
    }
}

fn decode_item(data: &[u8], pos: &mut usize, depth: usize) -> Result<Value, CborError> {
    if depth > MAX_DEPTH {
        return err("nesting too deep");
    }
    let ib = take(data, pos, 1)?[0];
    let major = ib >> 5;
    let info = ib & 0x1f;
    if major == 7 {
        return match info {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            _ => err("unsupported simple or float value"),
        };
    }
    let arg = read_arg(data, pos, info)?;
    match major {
        0 => {
            if arg > i64::MAX as u64 {
                return err("integer out of supported range");
            }
            Ok(Value::Int(arg as i64))
        }
        1 => {
            if arg > i64::MAX as u64 {
                return err("integer out of supported range");
            }
            Ok(Value::Int(-1 - arg as i64))
        }
        2 => {
            let n = usize::try_from(arg).map_err(|_| CborError("length overflow".into()))?;
            Ok(Value::Bytes(take(data, pos, n)?.to_vec()))
        }
        3 => {
            let n = usize::try_from(arg).map_err(|_| CborError("length overflow".into()))?;
            let s = std::str::from_utf8(take(data, pos, n)?)
                .map_err(|_| CborError("invalid utf-8 in text string".into()))?;
            Ok(Value::Text(s.to_string()))
        }
        4 => {
            let n = usize::try_from(arg).map_err(|_| CborError("length overflow".into()))?;
            if n > data.len() - *pos {
                return err("array length exceeds input");
            }
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(decode_item(data, pos, depth + 1)?);
            }
            Ok(Value::Array(v))
        }
        5 => {
            let n = usize::try_from(arg).map_err(|_| CborError("length overflow".into()))?;
            if n > data.len() - *pos {
                return err("map length exceeds input");
            }
            let mut v: Vec<(Value, Value)> = Vec::with_capacity(n);
            let mut prev: Option<&[u8]> = None;
            for _ in 0..n {
                let ks = *pos;
                let k = decode_item(data, pos, depth + 1)?;
                let kb = &data[ks..*pos];
                if let Some(p) = prev {
                    if kb <= p {
                        return err("map keys not in strictly increasing bytewise order");
                    }
                }
                prev = Some(kb);
                let val = decode_item(data, pos, depth + 1)?;
                v.push((k, val));
            }
            Ok(Value::Map(v))
        }
        6 => {
            let inner = decode_item(data, pos, depth + 1)?;
            Ok(Value::Tag(arg, Box::new(inner)))
        }
        _ => err("unreachable major type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8949_examples() {
        assert_eq!(Value::Int(0).encode(), [0x00]);
        assert_eq!(Value::Int(23).encode(), [0x17]);
        assert_eq!(Value::Int(24).encode(), [0x18, 0x18]);
        assert_eq!(Value::Int(1000).encode(), [0x19, 0x03, 0xe8]);
        assert_eq!(Value::Int(-1).encode(), [0x20]);
        assert_eq!(Value::Int(-70001).encode(), [0x3a, 0x00, 0x01, 0x11, 0x70]);
        assert_eq!(Value::text("a").encode(), [0x61, 0x61]);
    }

    #[test]
    fn map_keys_sorted_bytewise() {
        let m = Value::Map(vec![
            (Value::Int(-1), Value::Int(1)),
            (Value::Int(3), Value::Int(2)),
            (Value::Int(1), Value::Int(3)),
            (Value::Int(-2), Value::Int(4)),
        ]);
        assert_eq!(
            m.encode(),
            [0xa4, 0x01, 0x03, 0x03, 0x02, 0x20, 0x01, 0x21, 0x04]
        );
    }

    #[test]
    fn strict_decode_rejects_non_deterministic() {
        assert!(Value::decode(&[0x18, 0x05]).is_err());
        assert!(Value::decode(&[0x9f, 0xff]).is_err());
        assert!(Value::decode(&[0xa2, 0x02, 0x00, 0x01, 0x00]).is_err());
        assert!(Value::decode(&[0xa2, 0x01, 0x00, 0x01, 0x00]).is_err());
        assert!(Value::decode(&[0x00, 0x00]).is_err());
        assert!(Value::decode(&[0xf9, 0x00, 0x00]).is_err());
    }

    #[test]
    fn round_trip() {
        let v = Value::Tag(
            98,
            Box::new(Value::Array(vec![
                Value::bytes(b"abc"),
                Value::Map(vec![(Value::Int(-70005), Value::Null)]),
                Value::Bool(true),
            ])),
        );
        assert_eq!(Value::decode(&v.encode()).unwrap(), v);
    }
}
