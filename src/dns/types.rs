use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

/// DNS message structure
/// This structure represents a DNS message, which can be either a request or a response.
/// It contains a header, questions, answers, authorities, and additionals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// Transform the DNS message into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ctx = SerializationContext::default();
        let mut buffer = Vec::new();
        self.header.to_bytes(&mut buffer);
        for question in &self.questions {
            question.to_bytes(&mut ctx, &mut buffer);
        }
        for answer in &self.answers {
            answer.to_bytes(&mut ctx, &mut buffer);
        }
        for authority in &self.authorities {
            authority.to_bytes(&mut ctx, &mut buffer);
        }
        for additional in &self.additionals {
            additional.to_bytes(&mut ctx, &mut buffer);
        }
        buffer
    }

    /// Convert the DNS message's answers to a human-readable string in logger.
    /// This function iterates through the answers and formats them into a string.
    /// If there are no answers, it returns "<no answers>".
    pub fn response_data(&self) -> String {
        if self.answers.is_empty() {
            return String::from("<no answers>");
        }

        let mut result = Vec::new();

        for record in &self.answers {
            match &record.rdata {
                Rdata::A(ip) => {
                    result.push(format!("{}", ip));
                }
                Rdata::AAAA(ip) => {
                    result.push(format!("{}", ip));
                }
                Rdata::CNAME(name) => {
                    result.push(format!("CNAME {}", name));
                }
                Rdata::MX {
                    preference,
                    exchange,
                } => {
                    result.push(format!("MX {} {}", preference, exchange));
                }
                Rdata::NS(name) => {
                    result.push(format!("NS {}", name));
                }
                Rdata::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                } => {
                    result.push(format!(
                        "SOA {} {} {} {} {} {} {}",
                        mname, rname, serial, refresh, retry, expire, minimum
                    ));
                }
                Rdata::TXT(data) => {
                    // 尝试将TXT记录转为字符串
                    match String::from_utf8(data.clone()) {
                        Ok(s) => result.push(format!("TXT \"{}\"", s)),
                        Err(_) => result.push(format!("TXT <binary data: {} bytes>", data.len())),
                    }
                }
                Rdata::Unknown(_) => {
                    result.push(String::from("<unknown record type>"));
                }
            }
        }

        result.join(", ")
    }
    /// Set the DNS message's answer section.
    /// This function sets the answer section of the DNS message to the provided answer.
    /// It also updates the header to indicate that this is a response message.
    /// If recursion is desired, it sets the recursion available flag.
    /// Finally, it sets the response code to NoError.
    pub fn set_answer(&mut self, answer: Vec<ResourceRecord>) {
        self.header.to_response();
        self.header.answer_count = answer.len() as u16;
        self.answers = answer;
        self.header.set_response_code(ResponseCode::NoError);
        if self.header.recursion_desired() {
            self.header.set_recursion_avaliable();
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub id: u16,               // Packet ID
    pub flags: u16,            // Flags for the message
    pub question_count: u16,   // QDCOUNT
    pub answer_count: u16,     // ANCOUNT
    pub authority_count: u16,  // NSCOUNT
    pub additional_count: u16, // ARCOUNT
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    pub qname: String,       // Domain name
    pub qtype: QueryType,    // Type of query
    pub qclass: RecordClass, // Class of query
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,        // Domain name
    pub rtype: RecordType,   // Type of record
    pub rclass: RecordClass, // Class of record
    pub ttl: u32,            // Time to live(seconds)
    pub rdata: Rdata,        // Resource data
}

/// Resource data types
/// This enum represents the different types of resource data that can be associated with a DNS record.
/// 
/// - `A`: IPv4 address
/// - `AAAA`: IPv6 address
/// - `CNAME`: Canonical name
/// - `MX`: Mail exchange record
/// - `NS`: Name server record
/// - `SOA`: Start of authority record
/// - `TXT`: Text record
/// - 'Unknown'
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rdata {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    MX {
        preference: u16,
        exchange: String,
    },
    NS(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    TXT(Vec<u8>),
    Unknown(Vec<u8>),
}

/// Record types
/// This enum represents the different types of DNS records.
/// - `A`: IPv4 address
/// - `NS`: Name server
/// - `CNAME`: Canonical name
/// - `SOA`: Start of authority
/// - `PTR`: Pointer
/// - `MX`: Mail exchange
/// - `TXT`: Text
/// - `AAAA`: IPv6 address
/// - 'Unknown'
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    Unknown(u16),
}

/// Query types
/// This enum represents the different types of DNS queries.
/// - `A`: IPv4 address
/// - `NS`: Name server
/// - `CNAME`: Canonical name
/// - `SOA`: Start of authority
/// - `PTR`: Pointer
/// - `MX`: Mail exchange
/// - `TXT`: Text
/// - `AAAA`: IPv6 address
/// - `ANY`: Any type
/// - 'Unknown'
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum QueryType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    ANY = 255,
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordClass {
    IN = 1, // Internet
    Unknown(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpCode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    Unknown(u8),
}

/// Response codes
/// This enum represents the different response codes that can be returned in a DNS message.
/// - `NoError`: No error
/// - `FormErr`: Format error
/// - `ServFail`: Server failure
/// - `NXDomain`: Non-existent domain
/// - `NotImp`: Not implemented
/// - `Refused`: Refused
/// - `Unknown`: Unknown error
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    Unknown(u8),
}

impl Header {
    pub fn is_response(&self) -> bool {
        (self.flags >> 15) & 1 == 1
    }
    pub fn opcode(&self) -> OpCode {
        OpCode::from_u8(((self.flags >> 11) & 0b1111) as u8)
    }
    pub fn is_authoritative_answer(&self) -> bool {
        (self.flags >> 10) & 1 == 1
    }
    pub fn is_truncated(&self) -> bool {
        (self.flags >> 9) & 1 == 1
    }
    pub fn recursion_desired(&self) -> bool {
        (self.flags >> 8) & 1 == 1
    }
    pub fn recursion_available(&self) -> bool {
        (self.flags >> 7) & 1 == 1
    }
    pub fn response_code(&self) -> ResponseCode {
        ResponseCode::from_u8((self.flags & 0b1111) as u8)
    }
    pub fn set_response_code(&mut self, code: ResponseCode) {
        self.flags = (self.flags & !0b1111) | (code.to_u8() as u16);
    }
    pub fn to_response(&mut self) {
        self.flags |= 1 << 15;
    }
    pub fn set_recursion_avaliable(&mut self) {
        self.flags |= 1 << 8;
    }


    /// Convert the header to bytes.
    /// This function converts the header fields into bytes and appends them to the provided buffer.
    /// It uses big-endian byte order for multi-byte fields.
    pub fn to_bytes(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.id.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_be_bytes());
        buffer.extend_from_slice(&self.question_count.to_be_bytes());
        buffer.extend_from_slice(&self.answer_count.to_be_bytes());
        buffer.extend_from_slice(&self.authority_count.to_be_bytes());
        buffer.extend_from_slice(&self.additional_count.to_be_bytes());
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let type_u16 = self.to_u16();
        QueryType::from_u16(type_u16).fmt(f)
    }
}

impl RecordType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            _ => RecordType::Unknown(val),
        }
    }
    pub fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::Unknown(val) => *val,
        }
    }
}

impl Question {
    /// Convert the question to bytes.
    /// This function converts the question fields into bytes and appends them to the provided buffer.
    /// It uses the `SerializationContext` to handle domain name serialization.
    /// It uses big-endian byte order for multi-byte fields.
    /// The `buf_offset` parameter is used to handle domain name compression.
    fn to_bytes(&self, ctx: &mut SerializationContext, buffer: &mut Vec<u8>) {
        ctx.write_domain_name(&self.qname, buffer, 0);
        buffer.extend_from_slice(&self.qtype.to_u16().to_be_bytes());
        buffer.extend_from_slice(&self.qclass.to_u16().to_be_bytes());
    }
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use QueryType::*;
        match self {
            A => {
                write!(f, "A")
            }
            AAAA => {
                write!(f, "AAAA")
            }
            CNAME => {
                write!(f, "CNAME")
            }
            SOA => {
                write!(f, "SOA")
            }
            PTR => {
                write!(f, "PTR")
            }
            NS => {
                write!(f, "NS")
            }
            MX => {
                write!(f, "MX")
            }
            TXT => {
                write!(f, "TXT")
            }
            ANY => {
                write!(f, "ANY")
            }
            Unknown(_) => {
                write!(f, "Unknown")
            }
        }
    }
}

impl QueryType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            12 => QueryType::PTR,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            28 => QueryType::AAAA,
            255 => QueryType::ANY,
            _ => QueryType::Unknown(val),
        }
    }
    pub fn to_u16(&self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::PTR => 12,
            QueryType::MX => 15,
            QueryType::TXT => 16,
            QueryType::AAAA => 28,
            QueryType::ANY => 255,
            QueryType::Unknown(val) => *val,
        }
    }
}

impl RecordClass {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordClass::IN,
            _ => RecordClass::Unknown(val),
        }
    }
    pub fn to_u16(&self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::Unknown(val) => *val,
        }
    }
}

impl OpCode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            4 => OpCode::Notify,
            5 => OpCode::Update,
            _ => OpCode::Unknown(val as u8),
        }
    }
}

impl std::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ResponseCode::*;
        match self {
            NoError => {
                write!(f, "NoError")
            }
            FormErr => {
                write!(f, "FormErr")
            }
            ServFail => {
                write!(f, "ServFail")
            }
            NXDomain => {
                write!(f, "NXDomain")
            }
            NotImp => {
                write!(f, "NotImp")
            }
            Refused => {
                write!(f, "Refused")
            }
            Unknown(_) => {
                write!(f, "Unknown")
            }
        }
    }
}

impl ResponseCode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            _ => ResponseCode::Unknown(val),
        }
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            ResponseCode::NoError => 0,
            ResponseCode::FormErr => 1,
            ResponseCode::ServFail => 2,
            ResponseCode::NXDomain => 3,
            ResponseCode::NotImp => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Unknown(val) => *val,
        }
    }
}

impl Rdata {
    /// Convert the resource data to bytes.
    /// This function converts the resource data fields into bytes and appends them to the provided buffer.
    /// It uses the `SerializationContext` to handle domain name serialization.
    /// It uses big-endian byte order for multi-byte fields.
    /// The `buf_offset` parameter is used to handle domain name compression.
    fn to_bytes(&self, ctx: &mut SerializationContext, buffer: &mut Vec<u8>, buf_offset: u16) {
        match self {
            Rdata::A(ipv4_addr) => {
                buffer.extend_from_slice(&ipv4_addr.octets());
            }
            Rdata::AAAA(ipv6_addr) => {
                buffer.extend_from_slice(&ipv6_addr.octets());
            }
            Rdata::CNAME(domain) => {
                ctx.write_domain_name(domain, buffer, buf_offset);
            }
            Rdata::MX {
                preference,
                exchange,
            } => {
                buffer.extend_from_slice(&preference.to_be_bytes());
                ctx.write_domain_name(exchange, buffer, buf_offset);
            }
            Rdata::NS(domain) => {
                ctx.write_domain_name(domain, buffer, buf_offset);
            }
            Rdata::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                ctx.write_domain_name(mname, buffer, buf_offset);
                ctx.write_domain_name(rname, buffer, buf_offset);
                buffer.extend_from_slice(&serial.to_be_bytes());
                buffer.extend_from_slice(&refresh.to_be_bytes());
                buffer.extend_from_slice(&retry.to_be_bytes());
                buffer.extend_from_slice(&expire.to_be_bytes());
                buffer.extend_from_slice(&minimum.to_be_bytes());
            }
            Rdata::TXT(txt) => {
                buffer.extend_from_slice(txt);
            }
            Rdata::Unknown(items) => {
                buffer.extend_from_slice(items);
            }
        }
    }
}

impl ResourceRecord {
    /// Convert the resource record to bytes.
    /// This function converts the resource record fields into bytes and appends them to the provided buffer.
    /// It uses the `SerializationContext` to handle domain name serialization.
    /// It uses big-endian byte order for multi-byte fields.
    /// The `buf_offset` parameter is used to handle domain name compression.
    fn to_bytes(&self, ctx: &mut SerializationContext, buffer: &mut Vec<u8>) {
        ctx.write_domain_name(&self.name, buffer, 0);
        buffer.extend_from_slice(&self.rtype.to_u16().to_be_bytes());
        buffer.extend_from_slice(&self.rclass.to_u16().to_be_bytes());
        buffer.extend_from_slice(&self.ttl.to_be_bytes());
        let mut rdata: Vec<u8> = Vec::new();
        self.rdata
            .to_bytes(ctx, &mut rdata, buffer.len() as u16 + 2);
        buffer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&rdata);
    }
}

/// Serialization context for DNS messages
/// This struct is used to keep track of domain name pointers during serialization.
/// It helps in compressing domain names by replacing them with pointers to their previous occurrences.
/// The `domain_pointer` field is a hash map that maps domain names to their offsets in the buffer.
#[derive(Debug, Default)]
struct SerializationContext {
    domain_pointer: HashMap<String, u16>,
}

impl SerializationContext {
    /// Write a domain name to the buffer.
    /// This function serializes the domain name into the buffer.
    /// It uses compression if the domain name has been seen before.
    /// The `buf_offset` parameter is used to handle domain name compression.
    /// If the domain name is empty or just a dot, it writes a zero byte to the buffer.
    /// If the domain name has been seen before, it writes a pointer to the previous occurrence.
    /// Otherwise, it writes the length of each part of the domain name followed by the part itself.
    /// Finally, it writes a zero byte to indicate the end of the domain name.
    /// The `domain_pointer` field is updated with the current offset of the domain name in the buffer.
    fn write_domain_name(&mut self, domain: &str, buffer: &mut Vec<u8>, buf_offset: u16) {
        if domain.is_empty() || domain == "." {
            buffer.push(0);
            return;
        }

        let parts = domain.split('.');
        let mut cur_idx = 0;
        for part in parts {
            let len = part.len();
            let full_name = &domain[cur_idx..domain.len()];
            cur_idx += len + 1;
            if let Some(&offset) = self.domain_pointer.get(full_name) {
                buffer.extend_from_slice(&(0xC000 | (offset)).to_be_bytes());
                return;
            }

            self.domain_pointer
                .insert(full_name.to_owned(), buffer.len() as u16 + buf_offset);
            buffer.push(len as u8);
            buffer.extend_from_slice(part.as_bytes());
        }
        buffer.push(0);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tokio::{net::UdpSocket, test};
    use tracing::info;
    use tracing_test::traced_test;

    use crate::dns::{frame::Frame, processor::Processor};

    #[test]
    #[traced_test]
    #[ignore]
    async fn test_to_bytes() {
        let socket = UdpSocket::bind("127.0.0.1:8853").await.unwrap();
        let mut buf = [0; 512];
        let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
        let bytes = &buf[..len].to_vec();
        info!(?bytes);
        let mut cursor = Cursor::new(&bytes[..]);
        let mut processor = Processor::new();
        let message = processor.parse_message(&mut cursor).await;
        info!(?message);
        assert!(message.is_ok());
        let messgae = message.unwrap();
        let bytes = match &messgae {
            Frame::Request(msg) => {
                let bytes = msg.to_bytes();
                assert!(!bytes.is_empty());
                info!(?bytes);
                bytes
            }
            Frame::Response(msg) => {
                let bytes = msg.to_bytes();
                assert!(!bytes.is_empty());
                info!(?bytes);
                bytes
            }
        };
        let mut cursor = Cursor::new(&bytes[..]);
        let mut parser = Processor::new();
        let frame = parser.parse_message(&mut cursor).await;
        info!(?frame);
        assert!(frame.is_ok());
        let frame = frame.unwrap();
        assert_eq!(&frame, &messgae);
    }
}
