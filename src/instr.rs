//! Inline small string: header names/values are short, so keeping them in the
//! struct avoids one heap allocation each (nginx parses headers in place).

use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

const INLINE: usize = 48;

pub enum Repr {
    Inline { len: u8, buf: [u8; INLINE] },
    Heap(Box<str>),
}

pub struct InStr(Repr);

impl InStr {
    pub fn new(s: &str) -> Self {
        if s.len() <= INLINE {
            let mut buf = [0u8; INLINE];
            buf[..s.len()].copy_from_slice(s.as_bytes());
            InStr(Repr::Inline {
                len: s.len() as u8,
                buf,
            })
        } else {
            InStr(Repr::Heap(s.into()))
        }
    }

    pub fn as_str(&self) -> &str {
        match &self.0 {
            Repr::Inline { len, buf } => {
                // SAFETY: only ever filled from &str via copy_from_slice.
                unsafe { std::str::from_utf8_unchecked(&buf[..*len as usize]) }
            }
            Repr::Heap(s) => s,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl Default for InStr {
    fn default() -> Self {
        InStr::new("")
    }
}

impl Deref for InStr {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for InStr {
    fn from(s: &str) -> Self {
        InStr::new(s)
    }
}

impl From<String> for InStr {
    fn from(s: String) -> Self {
        if s.len() <= INLINE {
            InStr::new(&s)
        } else {
            InStr(Repr::Heap(s.into_boxed_str()))
        }
    }
}

impl Clone for InStr {
    fn clone(&self) -> Self {
        match &self.0 {
            Repr::Inline { len, buf } => InStr(Repr::Inline {
                len: *len,
                buf: *buf,
            }),
            Repr::Heap(s) => InStr(Repr::Heap(s.clone())),
        }
    }
}

impl PartialEq for InStr {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for InStr {}

impl PartialEq<str> for InStr {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}
impl PartialEq<&str> for InStr {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}
impl PartialEq<InStr> for str {
    fn eq(&self, other: &InStr) -> bool {
        self == other.as_str()
    }
}

impl Hash for InStr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state)
    }
}

impl fmt::Display for InStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for InStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl std::borrow::Borrow<str> for InStr {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_and_heap() {
        let a = InStr::new("Host");
        assert_eq!(a.as_str(), "Host");
        let long = "x".repeat(INLINE + 10);
        let b = InStr::new(&long);
        assert_eq!(b.as_str(), long);
        assert_eq!(a, InStr::new("Host"));
        assert_eq!(b.clone().as_str(), long);
    }
}
