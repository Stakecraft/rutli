// Copyright 2026 StakeCraft
// SPDX-License-Identifier: Apache-2.0

//! A deliberately tiny, strict protobuf reader for the handful of frozen Canton v30 messages this
//! crate reads.
//!
//! Why not prost: prost (like every conforming protobuf decoder) silently skips unknown fields and
//! lets a repeated singular field win by "last one wins". For key material that is the wrong
//! default. A field we do not know about may be a future format we would misinterpret, so every
//! message parser here refuses unknown field numbers, unexpected wire types and duplicated singular
//! fields, and says which one. The messages are small and frozen (proto package `v30`), so a
//! hand-written reader is shorter than the codegen plumbing and needs no build script.
//!
//! Only wire types 0 (varint) and 2 (length-delimited) occur in these messages; the others
//! (fixed64, fixed32, groups) are rejected outright.

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Field<'a> {
    pub number: u32,
    pub value: Value<'a>,
}

/// Split `buf` into its top-level fields. Fails on truncation, on overlong/overflowing varints,
/// on field number 0 and on any wire type other than 0 and 2.
pub(crate) fn fields<'a>(buf: &'a [u8], msg: &'static str) -> Result<Vec<Field<'a>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        let key = varint(buf, &mut pos, msg)?;
        let wire_type = (key & 0x7) as u8;
        let number = key >> 3;
        if number == 0 || number > u64::from(u32::MAX >> 3) {
            return Err(malformed(msg, format!("invalid field number {number}")));
        }
        let number = number as u32;
        let value = match wire_type {
            0 => Value::Varint(varint(buf, &mut pos, msg)?),
            2 => {
                let len = varint(buf, &mut pos, msg)?;
                let len = usize::try_from(len)
                    .map_err(|_| malformed(msg, format!("field {number}: length overflows")))?;
                let end = pos
                    .checked_add(len)
                    .filter(|end| *end <= buf.len())
                    .ok_or_else(|| malformed(msg, format!("field {number}: truncated")))?;
                let v = Value::Bytes(&buf[pos..end]);
                pos = end;
                v
            }
            other => {
                return Err(malformed(
                    msg,
                    format!("field {number}: wire type {other} does not occur in this message"),
                ))
            }
        };
        out.push(Field { number, value });
    }
    Ok(out)
}

fn varint(buf: &[u8], pos: &mut usize, msg: &'static str) -> Result<u64> {
    let mut v: u64 = 0;
    for i in 0..10 {
        let b = *buf.get(*pos).ok_or_else(|| malformed(msg, "truncated varint".into()))?;
        *pos += 1;
        if i == 9 && b > 1 {
            return Err(malformed(msg, "varint overflows 64 bits".into()));
        }
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            // Reject non-minimal encodings (a trailing zero group); no protobuf encoder emits them.
            if i > 0 && b == 0 {
                return Err(malformed(msg, "non-minimal varint".into()));
            }
            return Ok(v);
        }
    }
    Err(malformed(msg, "varint longer than 10 bytes".into()))
}

fn malformed(msg: &'static str, why: String) -> Error {
    Error::Malformed(format!("{msg}: {why}"))
}

/// Accumulates a message's fields with strict singular/repeated bookkeeping.
pub(crate) struct Msg<'a> {
    name: &'static str,
    fields: Vec<Field<'a>>,
}

impl<'a> Msg<'a> {
    pub fn parse(buf: &'a [u8], name: &'static str) -> Result<Self> {
        Ok(Self { name, fields: fields(buf, name)? })
    }

    /// Fail if any field number outside `known` is present.
    pub fn only(&self, known: &[u32]) -> Result<()> {
        for f in &self.fields {
            if !known.contains(&f.number) {
                return Err(malformed(
                    self.name,
                    format!("unknown field {} — refusing to guess at a newer format", f.number),
                ));
            }
        }
        Ok(())
    }

    fn singular(&self, number: u32) -> Result<Option<Value<'a>>> {
        let mut it = self.fields.iter().filter(|f| f.number == number);
        let first = it.next().map(|f| f.value);
        if it.next().is_some() {
            return Err(malformed(self.name, format!("field {number} occurs more than once")));
        }
        Ok(first)
    }

    /// A singular length-delimited field (bytes, string or sub-message). Absent → `None`.
    pub fn bytes(&self, number: u32) -> Result<Option<&'a [u8]>> {
        match self.singular(number)? {
            None => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b)),
            Some(Value::Varint(_)) => Err(self.wire_type_error(number)),
        }
    }

    /// A singular varint field (int32 / enum). Absent → proto3 default 0.
    pub fn varint(&self, number: u32) -> Result<u64> {
        match self.singular(number)? {
            None => Ok(0),
            Some(Value::Varint(v)) => Ok(v),
            Some(Value::Bytes(_)) => Err(self.wire_type_error(number)),
        }
    }

    /// A repeated enum field. Accepts both packed (wire type 2) and unpacked (wire type 0)
    /// encodings, as every protobuf parser must; scalapb writes packed.
    pub fn repeated_varint(&self, number: u32) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        for f in self.fields.iter().filter(|f| f.number == number) {
            match f.value {
                Value::Varint(v) => out.push(v),
                Value::Bytes(packed) => {
                    let mut pos = 0;
                    while pos < packed.len() {
                        out.push(varint(packed, &mut pos, self.name)?);
                    }
                }
            }
        }
        Ok(out)
    }

    fn wire_type_error(&self, number: u32) -> Error {
        malformed(self.name, format!("field {number} has the wrong wire type"))
    }
}

/// Unwrap Canton's `UntypedVersionedMessage { oneof wrapper { bytes data = 1; } int32 version = 2; }`
/// (`community/base/src/main/protobuf/com/digitalasset/canton/version/v1/untyped_versioned_message.proto:23-28`).
///
/// Every message this crate reads has exactly one proto version in Canton 3.6.1, `ProtoVersion(30)`
/// (`CryptoKeys.scala:164-170`, `Signing.scala:1753-1759`, `Encryption.scala:886-890`,
/// `PasswordBasedEncryption.scala:51-57`), so any other version is refused.
pub(crate) fn untyped_versioned(buf: &[u8]) -> Result<&[u8]> {
    let m = Msg::parse(buf, "UntypedVersionedMessage")?;
    m.only(&[1, 2])?;
    let version = m.varint(2)?;
    let data = m
        .bytes(1)?
        .ok_or_else(|| Error::Malformed("UntypedVersionedMessage: no data".into()))?;
    if version == 0 {
        return Err(Error::Malformed("UntypedVersionedMessage: no version".into()));
    }
    if version != 30 {
        return Err(Error::Unsupported(format!(
            "UntypedVersionedMessage version {version}; Canton 3.6.1 writes 30 for keys"
        )));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_are_strict() {
        // 300 = 0xac 0x02
        let mut pos = 0;
        assert_eq!(varint(&[0xac, 0x02], &mut pos, "t").unwrap(), 300);
        // Non-minimal encoding of 0.
        assert!(varint(&[0x80, 0x00], &mut 0, "t").is_err());
        // Truncated.
        assert!(varint(&[0x80], &mut 0, "t").is_err());
        // 11 continuation bytes.
        assert!(varint(&[0xff; 11], &mut 0, "t").is_err());
    }

    #[test]
    fn unsupported_wire_types_and_truncation_are_refused() {
        // field 1, wire type 5 (fixed32)
        assert!(fields(&[0x0d, 0, 0, 0, 0], "t").is_err());
        // field 1, length 5 but only 2 bytes follow
        assert!(fields(&[0x0a, 0x05, 0x01, 0x02], "t").is_err());
        // field number 0
        assert!(fields(&[0x02, 0x00], "t").is_err());
    }

    #[test]
    fn duplicates_and_unknown_fields_are_refused() {
        let dup = [0x08, 0x01, 0x08, 0x02];
        let m = Msg::parse(&dup, "t").unwrap();
        assert!(m.varint(1).is_err());

        let unknown = [0x08, 0x01, 0x18, 0x01];
        let m = Msg::parse(&unknown, "t").unwrap();
        assert!(m.only(&[1]).is_err());
        assert!(m.only(&[1, 3]).is_ok());
    }

    #[test]
    fn repeated_accepts_packed_and_unpacked() {
        // field 5 packed [1, 4] then unpacked 3
        let buf = [0x2a, 0x02, 0x01, 0x04, 0x28, 0x03];
        let m = Msg::parse(&buf, "t").unwrap();
        assert_eq!(m.repeated_varint(5).unwrap(), vec![1, 4, 3]);
    }
}
