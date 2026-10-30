use crate::net::TcpConnection;

const HTTP_PORT: u16 = 0x0080;
const HTTPS_PORT: u16 = 0x01B1;
const HTTP_VERSION: &str = "1.1";

#[derive(Debug)]
pub enum HttpError {
    InvalidAddress,
    TcpConnectionFailed,
    FailedToSendRequest,
    FailedToGetResponse,
}

pub struct Client;

impl Client {
    pub fn get(uri: &str) -> Result<(), HttpError> {
        // https://sub.domain.com/api/thing?key=value&key=value

        let url: &str;
        let port: &str;

        // [0]https :// [1]sub.domain.com/api/thing?key=value&key=value
        match uri.split_once("://") {
            Some(split) => {
                if split.0 == "http" {
                    port = "80"
                } else if split.0 == "https" {
                    port = "443"
                } else {
                    return Err(HttpError::InvalidAddress);
                }

                url = split.1;
            }
            // https:// or http:// omitted, use http by default
            // TODO: Implement TLS so https can be used by default
            None => {
                port = "80";
                url = uri;
            }
        }

        let path: &str;
        let host: &str;

        match url.split_once("/") {
            Some(s) => {
                path = s.1;
                host = s.0;
            }
            None => match url.split_once("?") {
                Some(s) => {
                    path = s.1;
                    host = s.0;
                }
                None => {
                    path = "";
                    host = url;
                }
            },
        }
        let addr = String::from(host) + ":" + port;

        let request = format!(
            "GET /{} HTTP/{}\r\nHost: {}\r\n\r\n",
            url_encode(path), HTTP_VERSION, host
        );

        let mut tcp_conn =
            TcpConnection::new(addr.as_str(), None).map_err(|_| HttpError::TcpConnectionFailed)?;

        tcp_conn
            .send(&request.into_bytes())
            .map_err(|_| HttpError::FailedToSendRequest)?;

        let resp = tcp_conn
            .receive()
            .map_err(|_| HttpError::FailedToGetResponse)?;

        println!("{:?}", resp);

        // TODO:
        //    Handle responses (remote FIN if connection: close in the request, HTTP response)
        //    Handle error codes
        //    JSON Parser
        //    Handle fragmentation or chunking (investigate)

        Ok(())
    }
    pub fn post() {}
    pub fn listen() {}
}

//sub.domain.com/api?q=one value&b=café
//becomes
//sub.domain.com/api?q=one%20value&b=caf%C3%A9
fn url_encode(s: &str) -> String {
    let mut encoded = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(b as char)
            }
            _ => encoded.push_str(&format!("%{:02X}", b)),
        }
    }
    encoded
}
