use http::{header, Response, StatusCode, Version};

use crate::client::flow::state::RecvResponse;
use crate::client::flow::Flow;
use crate::client::test::scenario::Scenario;
use crate::ext::HeaderIterExt;

// This is a complete response.
const RESPONSE: &[u8] = b"\
        HTTP/1.1 200 OK\r\n\
        Content-Length: 123\r\n\
        Content-Type: text/plain\r\n\
        \r\n";

#[test]
fn receive_incomplete_response() {
    // -1 to never reach the end
    for i in 14..RESPONSE.len() - 1 {
        let scenario = Scenario::builder().get("https://q.test").build();
        let mut flow = scenario.to_recv_response();

        let (input_used, maybe_response) = flow.try_response(&RESPONSE[..i]).unwrap();
        assert_eq!(input_used, 0);
        assert!(maybe_response.is_none());
        assert!(!flow.can_proceed());
    }
}

#[test]
fn receive_complete_response() {
    let scenario = Scenario::builder().get("https://q.test").build();
    let mut flow = scenario.to_recv_response();

    let (input_used, maybe_response) = flow.try_response(RESPONSE).unwrap();
    assert_eq!(input_used, 66);
    assert!(maybe_response.is_some());

    let response = maybe_response.unwrap();

    assert_eq!(response.version(), Version::HTTP_11);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH).unwrap(),
        "123"
    );
    assert!(response
        .headers()
        .iter()
        .has(header::CONTENT_TYPE, "text/plain"));

    assert!(flow.can_proceed());
}

#[test]
fn prepended_100_continue() {
    // In the case of expect-100-continue, there's a chance the 100-continue
    // arrives after we started sending the request body, in which case
    // we receive it before the actual response.
    let scenario = Scenario::builder()
        .post("https://q.test")
        .header("expect", "100-continue")
        .build();

    let mut flow = scenario.to_recv_response();

    // incomplete 100-continue should be ignored.
    let (input_used, maybe_response) = flow.try_response(b"HTTP/1.1 100 Continue\r\n").unwrap();
    assert_eq!(input_used, 0);
    assert!(maybe_response.is_none());
    assert!(!flow.can_proceed());

    // complete 100-continue should be consumed without producing a request
    let (input_used, maybe_response) = flow.try_response(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
    assert_eq!(input_used, 25);
    assert!(maybe_response.is_none());
    assert!(!flow.can_proceed());

    // full response after prepended 100-continue
    let (input_used, maybe_response) = flow.try_response(RESPONSE).unwrap();
    assert_eq!(input_used, 66);
    assert!(maybe_response.is_some());
    assert!(flow.can_proceed());
}

#[test]
fn expect_100_without_100_continue() {
    // In the case of expect-100-continue
    let scenario = Scenario::builder()
        .post("https://q.test")
        .header("expect", "100-continue")
        .build();

    let mut flow = scenario.to_recv_response();

    // full response and no 100-continue
    let (input_used, maybe_response) = flow.try_response(RESPONSE).unwrap();
    assert_eq!(input_used, 66);
    assert!(maybe_response.is_some());
    assert!(flow.can_proceed());
}

#[test]
fn incomplete_302() {
    const COOKIE_FIRST_HALF: &str = "Set-Cookie: a=b; domain=.q.test; expire";
    const COOKIE_SECOND_HALF: &str =
        "s=Sun, 02-Feb-2025 21:39:08 GMT; path=/; HttpOnly; secure\r\n";
    const BODY: &str = "\r\n0\r\n\r\n";

    fn mkreq(additional: &str) -> String {
        format!(
            "HTTP/1.1 302\r\n\
            Content-Type: text/html; charset=utf-8\r\n{}\
            Connection: keep-alive\r\n\
            Location: https://auth.q.test/fakepage\r\n\
            {}{}{}",
            additional, COOKIE_FIRST_HALF, COOKIE_SECOND_HALF, BODY,
        )
    }

    fn make_request_with_content_length() -> String {
        mkreq("Content-Length: 5\r\n")
    }

    fn make_request_with_transfer_encoding() -> String {
        mkreq("Transfer-Encoding: chunked\r\n")
    }

    // this should never pass
    fn invalid_request(req: &str) -> &str {
        &req[..req.len() - (COOKIE_SECOND_HALF.len() + BODY.len())]
    }

    // this should pass only on 3XX with no `Content-Length` and `Transfer-Encoding` headers
    fn non_standard_valid_request(req: &str) -> &str {
        &req[..req.len() - (COOKIE_FIRST_HALF.len() + COOKIE_SECOND_HALF.len() + BODY.len())]
    }

    fn validate(
        input: &str,
        validate: impl Fn(Flow<(), RecvResponse>, usize, Option<Response<()>>),
    ) {
        let scenario = Scenario::builder().post("https://q.test").build();
        let mut flow = scenario.to_recv_response();
        let (input_used, maybe_response) = flow.try_response(input.as_bytes()).unwrap();
        validate(flow, input_used, maybe_response);
    }

    // expect ok with `len` bytes consumed
    fn ok(len: usize) -> impl Fn(Flow<(), RecvResponse>, usize, Option<Response<()>>) {
        move |flow, input_used, maybe_response| {
            assert_eq!(input_used, len);
            assert!(maybe_response.is_some());
            assert!(flow.can_proceed());
        }
    }

    // expect fail
    fn ko(flow: Flow<(), RecvResponse>, input_used: usize, maybe_response: Option<Response<()>>) {
        assert_eq!(input_used, 0);
        assert!(maybe_response.is_none());
        assert!(!flow.can_proceed())
    }

    {
        let input = make_request_with_transfer_encoding();
        let preamble_len = input.len() - (BODY.len() - 2);
        // Standard 302
        validate(&input, ok(preamble_len));
        // Truncated header section
        validate(invalid_request(&input), ko);
        // Truncated but incomplete header section
        validate(non_standard_valid_request(&input), ko);
    }

    {
        let input = make_request_with_content_length();
        let preamble_len = input.len() - (BODY.len() - 2);
        // Standard 302
        validate(&input, ok(preamble_len));
        // Truncated header section
        validate(invalid_request(&input), ko);
        // Truncated but incomplete header section
        validate(non_standard_valid_request(&input), ko);
    }
}
