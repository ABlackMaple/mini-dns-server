use std::{io::{self, Cursor, ErrorKind}, net::SocketAddr, sync::Arc, time::{Duration, Instant}};

use tokio::net::UdpSocket;
use tracing::{debug, error, info};

use crate::{db::{Db, Key}, Result};

use super::{frame::{Frame, ParseError}, types::{Message, RecordType}};

/// Processor handles DNS queries and responses
/// # Fields
/// - `addr`: The address of the client
/// - `upstream`: The address of the upstream DNS server
/// - 'socket': The socket used to communicate with the client
#[derive(Debug)]
pub struct Processor {
    addr: SocketAddr,
    upstream: SocketAddr,
    socket: Arc<UdpSocket>,
}

impl Processor {
    pub fn new(addr: SocketAddr, upstream: SocketAddr, socket: Arc<UdpSocket>) -> Self{
        Self {
            addr,
            upstream,
            socket,
        }
    }

    /// Handles the DNS query
    /// # Arguments
    /// - `db`: The database to use for caching
    /// - `msg`: The DNS message to process
    /// # Returns
    /// - `Result<()>`: Ok if the query was processed successfully, Err otherwise
    pub(crate)  async fn apply(&self, db: &Db, msg: &Message) -> Result<()> {
        let start = Instant::now();
        let source;
        let response_code;
        let response_data;
        for question in &msg.questions {
            let name = question.qname.clone().to_lowercase();
            let qtype = question.qtype;
            let rtype = RecordType::from_u16(question.qtype.to_u16());

            let response = if let Some(entry) = db.get(&Key::new(name.clone(), rtype)).await {
                // Get the answer from the cache.
                // If the answer not found, check for NS records.
                let mut response = msg.clone();
                let answer = entry.to_answer();
                response.set_answer(answer);
                source = "cache";
                response
                
            } else if let Some(entry) = db.get(&Key::new(name.clone(), RecordType::NS)).await{
                // Get the answer with type 'NS' from the cache
                let mut response = msg.clone();
                let answer = entry.to_answer();
                response.set_answer(answer);
                source = "cache";
                response
            } else {
                // If the answer not found in the cache, query the upstream server.
                source = "upstream";
                self.query_upstream(db, msg).await?
            };

            debug!(?response);

            let response_buf = response.to_bytes();
            // Send the response to the client
            self.socket.send_to(&response_buf, self.addr).await?;

            response_code = response.header.response_code();
            response_data = response.response_data();

            
            let elapsed = start.elapsed();
            info!(
                client = %self.addr,
                query_type = %qtype,
                domain = %name,
                response = %response_code,
                source = %source,
                rtt_ms = %elapsed.as_millis(),
                data = ?response_data,
                "DNS query processed"
            );
            break;
        }

        Ok(())
    }

    /// Queries the upstream DNS server for the given message
    /// # Arguments
    /// - `db`: The database to use for caching
    /// - `msg`: The DNS message to query
    /// # Returns
    /// - `Result<Message>`: The response message from the upstream server
    /// # Errors
    /// - `io::Error`: If the query fails
    /// - `ParseError`: If the response is not a valid DNS message
    /// - `Result`: If the query fails
    async fn query_upstream(&self, db: &Db, msg: &Message) -> Result<Message> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let request = msg.to_bytes();
        let mut buf = vec![0; 512];
        socket.send_to(&request, self.upstream).await?;
        let (len, _) = match tokio::time::timeout(
            Duration::from_secs(5), 
            socket.recv_from(&mut buf),
        ).await {
            Ok(result) => {result}
            Err(e) => {
                error!(domain = %msg.questions[0].qname, query_type = %msg.questions[0].qtype, ?e, "timeout");
                self.send_server_failure(msg).await?;
                return Err(io::Error::new(ErrorKind::TimedOut, "DNS query timeout").into());
            }
        }?;
        let mut cursor = Cursor::new(&buf[..len]);
        let response = self.parse_message(&mut cursor).await?;
        match response {
            // Insert the response into the cache
            Frame::Response(response) => {
                if response.header.answer_count != 0 {
                    let key = Key::new(msg.questions[0].qname.clone(), RecordType::from_u16(msg.questions[0].qtype.to_u16()));
                    let duration = response.answers.iter()
                        .map(|answer| answer.ttl)
                        .min()
                        .unwrap_or(3600);
                    db.insert(key, response.answers.clone(), Some(Duration::from_secs(duration as u64))).await;
                }
                if response.header.authority_count != 0 {
                    let key = Key::new(response.authorities[0].name.clone(), response.authorities[0].rtype);
                    let duration = response.authorities.iter()
                        .map(|authority| authority.ttl)
                        .min()
                        .unwrap_or(3600);
                    db.insert(key, response.authorities.clone(), Some(Duration::from_secs(duration as u64))).await;
                }
                if response.header.additional_count != 0 {
                    let key = Key::new(response.additionals[0].name.clone(), response.additionals[0].rtype);
                    let duration = response.additionals.iter()
                        .map(|additional| additional.ttl)
                        .min()
                        .unwrap_or(3600);
                    db.insert(key, response.additionals.clone(), Some(Duration::from_secs(duration as u64))).await;
                }
                Ok(response)
            }
            Frame::Request(request) => {
                return Err(ParseError::InvalidHeader(format!("Expected response got: {:?}", request)).into())
            }
        }
    }

    /// Sends a server failure response to the client
    async fn send_server_failure(&self, original: &Message) -> Result<()> {
        let mut response = original.clone();
        response.header.to_response();
        response.header.set_response_code(super::types::ResponseCode::ServFail);
        let response_buf = response.to_bytes();
        self.socket.send_to(&response_buf, self.addr).await?;
        Ok(())
    }

    /// Parses a DNS message from the given buffer
    /// # Arguments
    /// - `src`: The buffer to parse the message from
    pub async fn parse_message(&self, src: &mut Cursor<&[u8]>) -> Result<Frame> {
        let mut header = Frame::parse_header(src)?;
        let mut questions = Vec::with_capacity(header.question_count as usize);
        let mut answers = Vec::with_capacity(header.answer_count as usize);
        let mut authorities = Vec::with_capacity(header.authority_count as usize);
        let mut additionals = Vec::with_capacity(header.additional_count as usize);
        for _ in 0..header.question_count {
            questions.push(Frame::parse_question(src)?);
        }
        for _ in 0..header.answer_count {
            answers.push(Frame::parse_resource_record(src)?);
        }
        for _ in 0..header.authority_count {
            authorities.push(Frame::parse_resource_record(src)?);
        }
        for _ in 0..header.additional_count {
            let additional = Frame::parse_resource_record(src);
            match additional {
                Ok(additional) => {
                    additionals.push(additional);
                },
                Err(ParseError::UnsupportedType(41)) => {
                    continue;
                },
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
        header.additional_count = additionals.len() as u16;
        let message = Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        };

        Ok(match message.header.is_response() {
            true => Frame::Response(message),
            false => Frame::Request(message),
        })
    }

    pub fn into_bytes(&self, msg: Message) -> Vec<u8> {
        msg.to_bytes()
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use tokio::net::UdpSocket;
    use tracing::info;
    use tracing_test::traced_test;

    use crate::dns::processor;

    #[tokio::test]
    #[traced_test]
    #[ignore]
    async fn test_parse_request() {
        let socket = UdpSocket::bind(format!("127.0.0.1:8853")).await.unwrap();
        let mut buf = [0; 512];
        let (len, _) = socket.recv_from(&mut buf).await.unwrap();
        let mut cursor = Cursor::new(&buf[..len]);
        let mut parser = processor::Processor::new();
        let frame = parser.parse_message(&mut cursor).await;
        info!(?frame);
        assert!(frame.is_ok());
    }

}