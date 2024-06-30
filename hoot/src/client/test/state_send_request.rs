use crate::client::flow::SendRequestResult;
use crate::Error;

use super::scenario::Scenario;
use super::TestSliceExt;

#[test]
fn write_request() {
    let scenario = Scenario::builder().get("https://q.test").build();

    let mut flow = scenario.to_send_request();

    assert!(!flow.can_proceed());

    let mut o = vec![0; 1024];

    let n = flow.write(&mut o).unwrap();
    assert_eq!(n, 32);

    let cmp = "\
        GET / HTTP/1.1\r\n\
        host: q.test\r\n\
        \r\n";

    assert_eq!(o[..n].as_str(), cmp);
    assert!(flow.can_proceed());
}

#[test]
fn short_buffer() {
    let scenario = Scenario::builder().get("https://q.test").build();

    let mut flow = scenario.to_send_request();

    assert!(!flow.can_proceed());

    // Buffer too short to hold entire request
    let mut output = vec![0; 10];

    let r = flow.write(&mut output);

    assert_eq!(r.unwrap_err(), Error::OutputOverflow);
    assert!(!flow.can_proceed());
}

#[test]
fn proceed_without_body() {
    let scenario = Scenario::builder().get("https://q.test").build();

    let mut flow = scenario.to_send_request();
    flow.write(&mut vec![0; 1024]).unwrap();

    match flow.proceed() {
        SendRequestResult::RecvResponse(_) => {}
        _ => panic!("Mehod without body should result in RecvResponse"),
    }
}

#[test]
fn proceed_with_body() {
    let scenario = Scenario::builder().post("https://q.test").build();

    let mut flow = scenario.to_send_request();
    flow.write(&mut vec![0; 1024]).unwrap();

    match flow.proceed() {
        SendRequestResult::SendBody(_) => {}
        _ => panic!("Method with body should result in SendBody"),
    }
}

#[test]
fn proceed_with_await_100() {
    let scenario = Scenario::builder()
        .post("https://q.test")
        .header("expect", "100-continue")
        .build();

    let mut flow = scenario.to_send_request();
    flow.write(&mut vec![0; 1024]).unwrap();

    match flow.proceed() {
        SendRequestResult::Await100(_) => {}
        _ => panic!("Method with body and Expect: 100-continue should result in Await100"),
    }
}

#[test]
fn proceed_without_body_and_expect_100() {
    let scenario = Scenario::builder()
        // GET should not result in Await100 since
        // there is no body to send.
        .get("https://q.test")
        .header("expect", "100-continue")
        .body("hello");

    let mut flow = scenario.to_send_request();
    flow.write(&mut vec![0; 1024]).unwrap();

    match flow.proceed() {
        SendRequestResult::RecvResponse(_) => {}
        _ => panic!("Method without body and Expect: 100-continue should result in RecvResponse"),
    }
}
