use std::{collections::HashSet, fmt, io::{self, Cursor}, net::{Ipv4Addr, Ipv6Addr}};
use bytes::Buf;

use super::types::{Header, Message, QueryType, Question, Rdata, RecordClass, RecordType, ResourceRecord};


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Request(Message),
    Response(Message),
}

#[derive(Debug)]
pub enum ParseError {
    /// Not enough data provided to parse the expected structure.
    UnexpectedEndOfBuffer,
    /// An I/O error occurred (e.g., reading from a stream).
    Io(io::Error),
    /// The header contains invalid data or flags.
    InvalidHeader(String),
    /// The domain name encoding is invalid (labels, pointers).
    InvalidNameEncoding(String),
    /// A pointer offset was invalid (out of bounds, points to header, etc.).
    InvalidPointerOffset(usize),
    /// A loop was detected in the name pointers.
    PointerLoopDetected,
    /// The RDATA for a resource record is invalid for its type.
    InvalidRecordData { rtype: u16, reason: String }, // Use RecordType enum if available
    /// An unsupported Query Type or Record Type was encountered.
    UnsupportedType(u16),
    /// An unsupported Query Class or Record Class was encountered.
    UnsupportedClass(u16),
    /// Generic parsing error.
    Message(String),
}

impl Frame {
    /// Parses a header from the given buffer.
    pub(crate) fn parse_header(src: &mut Cursor<&[u8]>) -> Result<Header, ParseError> {
        let id = get_u16(src)?;
        let flags = get_u16(src)?;
        let qdcount = get_u16(src)?;
        let ancount = get_u16(src)?;
        let nscount = get_u16(src)?;
        let arcount = get_u16(src)?;
        Ok(Header {
            id,
            flags,
            question_count: qdcount,
            answer_count: ancount,
            authority_count: nscount,
            additional_count: arcount,
        })
    }

    /// Parses questions from the given buffer.
    pub(crate) fn parse_question(src: &mut Cursor<&[u8]>) -> Result<Question, ParseError>{
        let qname = get_domain(src)?;
        let qtype = get_u16(src)?;
        let qclass = get_u16(src)?;
        let qtype = QueryType::from_u16(qtype);
        if let QueryType::Unknown(t) = qtype {
            return Err(ParseError::UnsupportedType(t));
        }
        let qclass = RecordClass::from_u16(qclass);
        if let RecordClass::Unknown(c) = qclass {
            return Err(ParseError::UnsupportedClass(c));
        }
        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }

    /// Parses a resource record from the given buffer.
    pub(crate) fn parse_resource_record(src: &mut Cursor<&[u8]>) -> Result<ResourceRecord, ParseError> {
        let name = get_domain(src)?;
        let rtype = get_u16(src)?;
        let rclass = get_u16(src)?;
        let ttl = get_u32(src)?;
        let rdlength = get_u16(src)?;
        let rtype = RecordType::from_u16(rtype);
        if let RecordType::Unknown(t) = rtype {
            return Err(ParseError::UnsupportedType(t));
        }
        let rclass = RecordClass::from_u16(rclass);
        if let RecordClass::Unknown(c) = rclass {
            skip(src, rdlength as usize)?;
            return Err(ParseError::UnsupportedClass(c));
        }
        let rdata = get_rdata(src, &rtype, rdlength)?;
        
        Ok(ResourceRecord { name, rtype, rclass, ttl, rdata })
    }
}

/// Parses the RDATA field based on the record type and length.
/// Returns the parsed RDATA as an enum variant.
fn get_rdata(src: &mut Cursor<&[u8]>, rtype: &RecordType, rdlength: u16) -> Result<Rdata, ParseError> {
    match rtype {
        RecordType::A => {
            if 4 != rdlength {
                return Err(ParseError::InvalidRecordData {
                    rtype: rtype.to_u16(),
                    reason: format!("Expected 4 bytes for A record, got {}", rdlength),
                });
            }
            let addr = get_u32(src)?;
            let addr = Ipv4Addr::from_bits(addr);
            Ok(Rdata::A(addr))
        },
        RecordType::AAAA => {
            if 16 != rdlength {
                return Err(ParseError::InvalidRecordData {
                    rtype: rtype.to_u16(),
                    reason: format!("Expected 16 bytes for AAAA record, got {}", rdlength),
                });
            }
            let addr = get_bytes(src, 16)?;
            let addr: [u8; 16] = addr.try_into().unwrap();
            let addr = Ipv6Addr::from(addr);
            Ok(Rdata::AAAA(addr))
        },
        RecordType::CNAME | RecordType::NS => {
            let begin_pos = src.position();
            let domain = get_domain(src)?;
            if rdlength as u64 != (src.position() - begin_pos) {
                return Err(ParseError::InvalidRecordData { 
                    rtype: rtype.to_u16(),
                    reason: format!("Expected {} bytes for CNAME/NS record", rdlength) })
            } 
            if rtype == &RecordType::CNAME {
                Ok(Rdata::CNAME(domain))
            } else {
                Ok(Rdata::NS(domain))
            }
        },
        RecordType::MX => {
            if rdlength < 3 {
                return Err(ParseError::InvalidRecordData { rtype: rtype.to_u16(), reason: "MX record too short".to_string() });
            }
            let preference = get_u16(src)?;
            let begin_pos = src.position();
            let domain = get_domain(src)?;
            if rdlength as u64 != (src.position() - begin_pos) {
                return Err(ParseError::InvalidRecordData { 
                    rtype: rtype.to_u16(),
                    reason: format!("Expected {} bytes for MX record", rdlength) })
            }
            Ok(Rdata::MX { preference, exchange: domain })
        },
        RecordType::SOA => {
            if rdlength < 22 {
                return Err(ParseError::InvalidRecordData { rtype: rtype.to_u16(), reason: "SOA record too short".to_string() });
            }
            let mname = get_domain(src)?;
            let rname = get_domain(src)?;
            let serial = get_u32(src)?;
            let refresh = get_u32(src)?;
            let retry = get_u32(src)?;
            let expire = get_u32(src)?;
            let minimum = get_u32(src)?;
            Ok(Rdata::SOA { mname, rname, serial, refresh, retry, expire, minimum })
        },
        RecordType::TXT => {
            // let mut combined_data = Vec::with_capacity(rdlength as usize);
            // let mut bytes_read = 0;
            // while bytes_read < rdlength as usize {
            //     let segment_len = get_u8(src)?;
            //     bytes_read += 1;
            //     if segment_len as usize > (rdlength as usize).saturating_sub(bytes_read) {
            //         return Err(
            //             ParseError::InvalidRecordData {
            //                 rtype: rtype.to_u16(),
            //                 reason: format!(
            //                     "Invalid segment length {} for TXT record, remaining bytes: {}",
            //                     segment_len,
            //                     rdlength as usize - bytes_read
            //                 )
            //             }
            //         )
            //     }
            //     if segment_len > 0 {
            //         let data_segment = get_bytes(src, segment_len as usize)?;
            //         combined_data.extend_from_slice(data_segment);
            //         bytes_read += segment_len as usize;
            //     }   
            // }
            // let txt = String::from_utf8(combined_data).map_err(
            //     |e| ParseError::InvalidNameEncoding(format!("Invalid UTF-8 in TXT record: {}", e))
            // )?;
            let txt = get_bytes(src, rdlength as usize)?;
            Ok(Rdata::TXT(txt.to_vec()))
        },
        _ => {
            Ok(Rdata::Unknown(get_bytes(src, rdlength as usize)?.to_vec()))
        }
    }
}

/// Parses a domain name from the given buffer.
/// Handles pointers and labels according to the DNS protocol.
/// Returns the parsed domain name as a String.
fn get_domain(src: &mut Cursor<&[u8]>) -> Result<String, ParseError> {
    let mut domain = String::new();
    let mut end_pos = src.position();
    let mut ptr_pos = HashSet::new();
    while let Ok(label_len) = peek_u8(src) {
        if label_len == 0 {
            skip(src, 1)?;
            break;
        }
        if label_len & 0xC0 == 0xC0 {
            let ptr = get_u16(src)? & 0x3FFF;
            if ptr as u64 >= end_pos || ptr_pos.contains(&ptr) {
                return Err(ParseError::InvalidPointerOffset(ptr as usize));
            }
            ptr_pos.insert(ptr);
            if end_pos < src.position() {
                end_pos = src.position();
            }
            src.set_position(ptr as u64);
            continue;
        }
        skip(src, 1)?;
        let bytes = get_bytes(src, label_len as usize)?;
        let label = std::str::from_utf8(bytes).map_err(
            |e| ParseError::InvalidNameEncoding(format!("Invalid UTF-8 in label: {}", e))
        )?;
        if !domain.is_empty() {
            domain.push('.');
        }
        domain.push_str(label);
    }
    if end_pos > src.position() {
        src.set_position(end_pos as u64);
    }
    Ok(domain)
}

/// Helper function to peek at the next byte in the buffer without advancing the cursor.
fn peek_u8(src: &mut Cursor<&[u8]>) -> Result<u8, ParseError> {
    if !src.has_remaining() {
        return Err(ParseError::UnexpectedEndOfBuffer);
    }
    Ok(src.chunk()[0])
}
/// Helper function to get a byte from the buffer and advance the cursor.
#[allow(dead_code)]
fn get_u8(src: &mut Cursor<&[u8]>) -> Result<u8, ParseError> { 
    if !src.has_remaining() { 
        return Err(ParseError::UnexpectedEndOfBuffer); 
    } 
    Ok(src.get_u8()) 
} 
/// Helper function to peek at the next u16 in the buffer without advancing the cursor.
#[allow(dead_code)]
fn peek_u16(src:&mut Cursor<&[u8]>) -> Result<u16, ParseError> {
    if src.remaining() < 2 {
        return Err(ParseError::UnexpectedEndOfBuffer);
    }
    let pos = src.position() as u64;
    let val = src.get_u16();
    src.set_position(pos);
    Ok(val)
}
/// Helper function to get a u16 from the buffer and advance the cursor.
fn get_u16(src:&mut Cursor<&[u8]>) -> Result<u16, ParseError> {
    if src.remaining() < 2 {
        return Err(ParseError::UnexpectedEndOfBuffer);
    }
    Ok(src.get_u16())
}
/// Helper function to get a slice of bytes from the buffer and advance the cursor.
fn get_bytes<'a>(src: &mut Cursor<&'a [u8]>, len: usize) -> Result<&'a [u8], ParseError> {
    if src.remaining() < len {
        return Err(ParseError::UnexpectedEndOfBuffer);
    }
    let pos = src.position() as usize;
    let bytes = &src.get_ref()[pos..pos + len];
    src.set_position((pos + len) as u64);
    Ok(bytes)
}
/// Helper function to peek at the next u32 in the buffer without advancing the cursor.
#[allow(dead_code)]
fn peek_u32(src: &mut Cursor<&[u8]>) -> Result<u32, ParseError> {
    if src.remaining() < 4 {
        return Err(ParseError::UnexpectedEndOfBuffer);
    }
    let pos = src.position() as u64;
    let val = src.get_u32();
    src.set_position(pos);
    Ok(val)
}

/// Helper function to get a u32 from the buffer and advance the cursor.
fn get_u32(src: &mut Cursor<&[u8]>) -> Result<u32, ParseError> {
    if src.remaining() < 4 {
        return Err(ParseError::UnexpectedEndOfBuffer);
    }
    Ok(src.get_u32())
}
/// Helper function to skip a number of bytes in the buffer.
/// Advances the cursor by the specified number of bytes.
fn skip(src: &mut Cursor<&[u8]>, n: usize) -> Result<(), ParseError> {
    if src.remaining() < n {
        return Err(ParseError::UnexpectedEndOfBuffer)
    }
    src.advance(n);
    Ok(())
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnexpectedEndOfBuffer => write!(f, "Unexpected end of buffer"),
            ParseError::Io(e) => write!(f, "I/O error: {}", e),
            ParseError::InvalidHeader(reason) => write!(f, "Invalid DNS header: {}", reason),
            ParseError::InvalidNameEncoding(reason) => write!(f, "Invalid DNS name encoding: {}", reason),
            ParseError::InvalidPointerOffset(offset) => write!(f, "Invalid DNS name pointer offset: {}", offset),
            ParseError::PointerLoopDetected => write!(f, "DNS name pointer loop detected"),
            ParseError::InvalidRecordData { rtype, reason } => write!(f, "Invalid RDATA for type {}: {}", rtype, reason),
            ParseError::UnsupportedType(t) => write!(f, "Unsupported DNS type: {}", t),
            ParseError::UnsupportedClass(c) => write!(f, "Unsupported DNS class: {}", c),
            ParseError::Message(msg) => write!(f, "DNS parsing error: {}", msg),
        }
    }
}
impl std::error::Error for ParseError {}

impl From<io::Error> for ParseError {
    fn from(err: io::Error) -> Self {
        ParseError::Io(err)
    }
    
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use std::{io::Cursor, net::{Ipv4Addr, Ipv6Addr}};

    use crate::dns::{frame::{get_domain, Frame, ParseError}, types::{QueryType, Rdata, RecordClass, RecordType}};

    fn create_domain_bytes(domain: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    if domain.is_empty() || domain == "." {
        bytes.push(0);
        return bytes;
    }
    for label in domain.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes
}


    #[test]
    #[ignore]
    fn test_get_domain_simple() {
        let mut domain_bytes = create_domain_bytes("www.example.com");
        domain_bytes.push(0xC0); // Pointer to the start of the domain
        domain_bytes.push(0x00); // Pointer offset
        domain_bytes.push(3);
        domain_bytes.push(b't');
        domain_bytes.push(b't');
        domain_bytes.push(b't');
        domain_bytes.push(0xC0);
        domain_bytes.push(0x11);
        
        let mut cursor = Cursor::new(&domain_bytes[..]);
        let domain = get_domain(&mut cursor);
        
        assert!(domain.is_ok());
        assert_eq!(domain.unwrap(), "www.example.com");

        let domain = get_domain(&mut cursor);
        assert!(domain.is_ok());
        assert_eq!(domain.unwrap(), "www.example.com");

        let domain = get_domain(&mut cursor);
        assert!(domain.is_ok());
        assert_eq!(domain.unwrap(), "ttt.www.example.com");
        assert_eq!(cursor.position(), domain_bytes.len() as u64);

    }
    #[test]
    #[ignore]
    fn test_get_domain_root() {
        let domain_bytes = create_domain_bytes("");
        let mut cursor = Cursor::new(&domain_bytes[..]);
        let domain = get_domain(&mut cursor);
        assert!(domain.is_ok());
        assert_eq!(domain.unwrap(), "");
        assert_eq!(cursor.position(), domain_bytes.len() as u64);
    }

    #[test]
    #[ignore]
    fn test_get_domain_invalid_utf8() {
        let mut domain_bytes = Vec::new();
        domain_bytes.push(3);
        domain_bytes.push(b'\xFF'); // Invalid UTF-8 byte
        domain_bytes.push(0xC0);
        domain_bytes.push(0x11);
        
        let mut cursor = Cursor::new(&domain_bytes[..]);
        let domain = get_domain(&mut cursor);
        
        assert!(domain.is_err());
    }

    #[ignore]
    #[test]
    fn test_get_header() {
        let mut header_bytes = Vec::new();
        header_bytes.extend_from_slice(&[0x12, 0x34]); // ID
        header_bytes.extend_from_slice(&[0x01, 0x02]); // Flags
        header_bytes.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        header_bytes.extend_from_slice(&[0x00, 0x02]); // ANCOUNT
        header_bytes.extend_from_slice(&[0x00, 0x03]); // NSCOUNT
        header_bytes.extend_from_slice(&[0x00, 0x04]); // ARCOUNT
        
        let mut cursor = Cursor::new(&header_bytes[..]);
        let header = Frame::parse_header(&mut cursor);
        
        assert!(header.is_ok());
        let header = header.unwrap();
        assert_eq!(header.id, 0x1234);
        assert_eq!(header.flags, 0x0102);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_count, 2);
        assert_eq!(header.authority_count, 3);
        assert_eq!(header.additional_count, 4);
    }

    #[test]
    #[ignore]
    fn test_get_question() {
        let mut question_bytes = Vec::new();
        question_bytes.extend_from_slice(&[3, b'w', b'w', b'w']); // QNAME
        question_bytes.push(0x00); // QNAME end
        question_bytes.extend_from_slice(&[0x00, 0x01]); // QTYPE
        question_bytes.extend_from_slice(&[0x00, 0x01]); // QCLASS
        
        let mut cursor = Cursor::new(&question_bytes[..]);
        let question = Frame::parse_question(&mut cursor);
        
        assert!(question.is_ok());
        let question = question.unwrap();
        assert_eq!(question.qname, "www");
        assert_eq!(question.qtype, QueryType::A);
        assert_eq!(question.qclass, RecordClass::IN);
    }

    #[test]
    #[ignore]
    fn test_get_resource_record_a() {
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[3, b'w', b'w', b'w']); // NAME
        record_bytes.push(0x00); // NAME end
        record_bytes.extend_from_slice(&[0x00, 0x01]); // TYPE
        record_bytes.extend_from_slice(&[0x00, 0x01]); // CLASS
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // TTL
        record_bytes.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        record_bytes.extend_from_slice(&[192, 168, 1, 1]); // RDATA
        
        let mut cursor = Cursor::new(&record_bytes[..]);
        let record = Frame::parse_resource_record(&mut cursor);
        
        assert!(record.is_ok());
        let record = record.unwrap();
        assert_eq!(record.name, "www");
        assert_eq!(record.rtype, RecordType::A);
        assert_eq!(record.rclass, RecordClass::IN);
        assert_eq!(record.ttl, 1);
        assert_eq!(record.rdata, Rdata::A(Ipv4Addr::new(192, 168, 1, 1)));
    }
    #[test]
    #[ignore]
    fn test_get_resource_record_aaaa() {
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[3, b'w', b'w', b'w']); // NAME
        record_bytes.push(0x00); // NAME end
        record_bytes.extend_from_slice(&[0x00, 0x1C]); // TYPE
        record_bytes.extend_from_slice(&[0x00, 0x01]); // CLASS
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // TTL
        record_bytes.extend_from_slice(&[0x00, 0x10]); // RDLENGTH
        record_bytes.extend_from_slice(&[32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]); // RDATA
        
        let mut cursor = Cursor::new(&record_bytes[..]);
        let record = Frame::parse_resource_record(&mut cursor);
        
        assert!(record.is_ok());
        let record = record.unwrap();
        assert_eq!(record.name, "www");
        assert_eq!(record.rtype, RecordType::AAAA);
        assert_eq!(record.rclass, RecordClass::IN);
        assert_eq!(record.ttl, 1);
        assert_eq!(record.rdata, Rdata::AAAA(Ipv6Addr::from([32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])));
    }
    #[test]
    #[ignore]
    fn test_get_resource_record_cname() {
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[3, b'w', b'w', b'w']); // NAME
        record_bytes.push(0x00); // NAME end
        record_bytes.extend_from_slice(&[0x00, 0x05]); // TYPE
        record_bytes.extend_from_slice(&[0x00, 0x01]); // CLASS
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // TTL
        record_bytes.extend_from_slice(&[0x00, 0x05]); // RDLENGTH
        record_bytes.extend_from_slice(&[3, b'c', b'o', b'm', 0]); // RDATA
        
        let mut cursor = Cursor::new(&record_bytes[..]);
        let record = Frame::parse_resource_record(&mut cursor);
        
        assert!(record.is_ok());
        let record = record.unwrap();
        assert_eq!(record.name, "www");
        assert_eq!(record.rtype, RecordType::CNAME);
        assert_eq!(record.rclass, RecordClass::IN);
        assert_eq!(record.ttl, 1);
        assert_eq!(record.rdata, Rdata::CNAME("com".to_string()));
    }
    #[test]
    #[ignore]
    fn test_get_resource_record_ns() {
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[3, b'w', b'w', b'w']); // NAME
        record_bytes.push(0x00); // NAME end
        record_bytes.extend_from_slice(&[0x00, 0x02]); // TYPE
        record_bytes.extend_from_slice(&[0x00, 0x01]); // CLASS
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // TTL
        record_bytes.extend_from_slice(&[0x00, 0x05]); // RDLENGTH
        record_bytes.extend_from_slice(&[3, b'n', b's', b'1', 0]); // RDATA
        
        let mut cursor = Cursor::new(&record_bytes[..]);
        let record = Frame::parse_resource_record(&mut cursor);
        
        assert!(record.is_ok());
        let record = record.unwrap();
        assert_eq!(record.name, "www");
        assert_eq!(record.rtype, RecordType::NS);
        assert_eq!(record.rclass, RecordClass::IN);
        assert_eq!(record.ttl, 1);
        assert_eq!(record.rdata, Rdata::NS("ns1".to_string()));
    }
    #[test]
    #[ignore]
    fn test_get_resource_record_mx() {
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[3, b'w', b'w', b'w']); // NAME
        record_bytes.push(0x00); // NAME end
        record_bytes.extend_from_slice(&[0x00, 0x0F]); // TYPE
        record_bytes.extend_from_slice(&[0x00, 0x01]); // CLASS
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // TTL
        record_bytes.extend_from_slice(&[0x00, 0x05]); // RDLENGTH
        record_bytes.extend_from_slice(&[0x00, 0x05]); // Preference
        record_bytes.extend_from_slice(&[3, b'm', b'x', b'1', 0]); // RDATA
        
        let mut cursor = Cursor::new(&record_bytes[..]);
        let record = Frame::parse_resource_record(&mut cursor);
        
        assert!(record.is_ok());
        let record = record.unwrap();
        assert_eq!(record.name, "www");
        assert_eq!(record.rtype, RecordType::MX);
        assert_eq!(record.rclass, RecordClass::IN);
        assert_eq!(record.ttl, 1);
        assert_eq!(record.rdata, Rdata::MX { preference: 5, exchange: "mx1".to_string() });
    }
    #[test]
    #[ignore]
    fn test_get_resource_record_soa() {
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[3, b'w', b'w', b'w']); // NAME
        record_bytes.push(0x00); // NAME end
        record_bytes.extend_from_slice(&[0x00, 0x06]); // TYPE
        record_bytes.extend_from_slice(&[0x00, 0x01]); // CLASS
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // TTL
        record_bytes.extend_from_slice(&[0x00, 0x1C]); // RDLENGTH
        record_bytes.extend_from_slice(&[3, b's', b'o', b'a', 0]); // MNAME
        record_bytes.extend_from_slice(&[3, b'r', b'n', b'd', 0]); // RNAME
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // SERIAL
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x03, 0xE8]); // REFRESH
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // RETRY
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x03, 0xE8]); // EXPIRE
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // MINIMUM
        
        let mut cursor = Cursor::new(&record_bytes[..]);
        let record = Frame::parse_resource_record(&mut cursor);
        
        assert!(record.is_ok());
        let record = record.unwrap();
        assert_eq!(record.name, "www");
        assert_eq!(record.rtype, RecordType::SOA);
        assert_eq!(record.rclass, RecordClass::IN);
        assert_eq!(record.ttl, 1);
        assert_eq!(record.rdata,
            Rdata::SOA { mname: "soa".to_string(), rname: "rnd".to_string(), serial: 300,
                refresh: 1000,
                retry: 300,
                expire: 1000,
                minimum: 300,
        });
    }
    #[test]
    #[ignore]
    fn test_get_resource_record_txt() {
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[3, b'w', b'w', b'w']); // NAME
        record_bytes.push(0x00); // NAME end
        record_bytes.extend_from_slice(&[0x00, 0x10]); // TYPE
        record_bytes.extend_from_slice(&[0x00, 0x01]); // CLASS
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // TTL
        record_bytes.extend_from_slice(&[0x00, 0x0A]); // RDLENGTH
        record_bytes.extend_from_slice(&[5]); // Length of the first segment
        record_bytes.extend_from_slice(b"Hello"); // First segment of TXT data
        record_bytes.push(3); // Length of the second segment
        record_bytes.extend_from_slice(b"TXT"); // Second segment of TXT data
        
        let mut cursor = Cursor::new(&record_bytes[..]);
        let record = Frame::parse_resource_record(&mut cursor);
        
        assert!(record.is_ok());
        let record = record.unwrap();
        assert_eq!(record.name, "www");
        assert_eq!(record.rtype, RecordType::TXT);
        assert_eq!(record.rclass, RecordClass::IN);
        assert_eq!(record.ttl, 1);
        assert_eq!(record.rdata, Rdata::TXT([5, b'H', b'e', b'l', b'l', 3, b'T', b'X', b'T'].to_vec()));
    }
    #[test]
    #[ignore]
    fn test_get_resource_record_unknown() {
        let mut record_bytes = Vec::new();
        record_bytes.extend_from_slice(&[3, b'w', b'w', b'w']); // NAME
        record_bytes.push(0x00); // NAME end
        record_bytes.extend_from_slice(&[0x00, 0xFF]); // TYPE
        record_bytes.extend_from_slice(&[0x00, 0x01]); // CLASS
        record_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // TTL
        record_bytes.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        record_bytes.extend_from_slice(&[1, 2, 3, 4]); // RDATA
        
        let mut cursor = Cursor::new(&record_bytes[..]);
        let record = Frame::parse_resource_record(&mut cursor);
        
        assert!(record.is_err());
        let err = record.unwrap_err();
        assert_eq!(err.to_string(), "Unsupported DNS type: 255");
        if let ParseError::UnsupportedType(t) = err {
            assert_eq!(t, 255);
        }
    }
}