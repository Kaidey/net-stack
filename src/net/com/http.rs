use crate::net::TcpConnection;

const HTTP_PORT: u16 = 0x0080;
const HTTPS_PORT: u16 = 0x01B1;
const HTTP_VERSION: &str = "1.1";

#[derive(Debug)]
pub enum HttpError {
    InvalidAddress,
    TcpConnectionFailed,
    FailedToSendRequest
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
            None => {
                path = "/";
                host = url;
            }
        }

        let addr = String::from(host) + ":" + port;

        let request = format!("GET {} HTTP/{}\r\nHost: {}\r\n\r\n", path, HTTP_VERSION, host);

        let mut tcp_conn = TcpConnection::new(addr.as_str(), None).map_err(|_| HttpError::TcpConnectionFailed)?;

        tcp_conn.send(&request.into_bytes()).map_err(|_| HttpError::FailedToSendRequest)?;

        Ok(())
    }
    pub fn post() {}
    pub fn listen() {}
}
