// SPDX-License-Identifier: Apache-2.0

use automonique_platform_client::{ClientError, PlatformClient, PlatformTransport};
use automonique_protocol::codec::RequestId;
use automonique_protocol::platform::{Capabilities, PlatformRequest, PlatformResponse};

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
