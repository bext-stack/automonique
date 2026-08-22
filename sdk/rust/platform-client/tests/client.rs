// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use automonique_platform_client::{
    BearerToken, ClientError, HttpsTransport, PLATFORM_CONTENT_TYPE, PlatformClient,
    PlatformTransport,
};
use automonique_protocol::codec::RequestId;
use automonique_protocol::platform::{Capabilities, PlatformRequest, PlatformResponse};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};

struct FakeTransport {
    calls: usize,
}

impl PlatformTransport for FakeTransport {
    fn request(
        &mut self,
        request_id: RequestId,
        request: PlatformRequest,
    ) -> Result<PlatformResponse, ClientError> {
        assert_eq!(
            request_id.as_str(),
            format!("platform-client-{}", self.calls + 1)
        );
        self.calls += 1;
        assert!(matches!(request, PlatformRequest::Capabilities));
        Ok(PlatformResponse::Capabilities(Capabilities::platform_v1()))
    }
}

#[test]
fn facade_correlates_semantic_calls_without_transport_specific_models() {
    let mut client = PlatformClient::new(FakeTransport { calls: 0 });
    let capabilities = client.capabilities().expect("capabilities");
    assert_eq!(capabilities, Capabilities::platform_v1());
    assert_eq!(client.transport().calls, 1);
}

#[test]
fn https_transport_carries_the_canonical_frame_and_redacts_the_bearer() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("client connection");
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk).expect("request bytes");
            assert!(read > 0, "request ended before headers");
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = std::str::from_utf8(&bytes[..header_end]).expect("request headers");
        assert!(headers.starts_with("POST /platform HTTP/1.1\r\n"));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains(&format!("content-type: {PLATFORM_CONTENT_TYPE}\r\n"))
        );
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("authorization: bearer fixture-token\r\n")
        );
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .expect("content length");
        while bytes.len() < header_end + content_length {
            let read = stream.read(&mut chunk).expect("request body");
            assert!(read > 0, "request ended before body");
            bytes.extend_from_slice(&chunk[..read]);
        }
        let request = PlatformRequestMessage::from_canonical_bytes(
            &bytes[header_end..header_end + content_length],
        )
        .expect("canonical platform request");
        assert!(matches!(request.request(), PlatformRequest::Capabilities));
        let response = PlatformResponseMessage::new(
            request.request_id().clone(),
            PlatformResponse::Capabilities(Capabilities::platform_v1()),
        )
        .to_message()
        .expect("response frame")
        .to_canonical_bytes();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: {PLATFORM_CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .expect("response headers");
        stream.write_all(&response).expect("response body");
    });

    let token = BearerToken::new("fixture-token").expect("bounded token");
    let transport = HttpsTransport::new(format!("http://{address}/platform"), token)
        .expect("loopback endpoint");
    assert!(!format!("{transport:?}").contains("fixture-token"));
    let mut client = PlatformClient::new(transport);
    assert_eq!(
        client.capabilities().expect("remote capabilities"),
        Capabilities::platform_v1()
    );
    server.join().expect("server thread");
}

#[test]
fn https_transport_refuses_cleartext_remote_and_embedded_credentials() {
    let token = || BearerToken::new("fixture-token").expect("token");
    assert!(matches!(
        HttpsTransport::new("http://example.com/platform", token()),
        Err(ClientError::Endpoint)
    ));
    assert!(matches!(
        HttpsTransport::new("https://user@example.com/platform", token()),
        Err(ClientError::Endpoint)
    ));
    assert!(BearerToken::new("contains space").is_err());
}
