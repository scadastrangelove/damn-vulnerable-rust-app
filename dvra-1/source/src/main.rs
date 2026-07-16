//! Demo driver. Sends a few requests through the router so you can see the
//! service respond. This is NOT a server — it exists to make the target
//! runnable (`cargo run`) and to seed manual exploration.
//!
//! Educational use only. Do not deploy.

use dvr::{App, Request, Source};

fn req(path: &str, query: Vec<(&str, &str)>, headers: Vec<(&str, &str)>, body: &[u8]) -> Request {
    Request {
        principal: "alice".into(),
        is_admin: false,
        path: path.into(),
        query: query.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        headers: headers.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        body: body.to_vec(),
        source: Source::PublicEdge,
    }
}

fn main() {
    let app = App::new();

    let demos = vec![
        req("/users/search", vec![("username", "alice")], vec![], b""),
        req("/documents/get", vec![("id", "11")], vec![], b""),
        req("/files/download", vec![("name", "report.pdf")], vec![], b""),
        req("/validate", vec![("n", "42")], vec![], b""),
        req("/login", vec![], vec![("x-token", "nope")], b""),
    ];

    for r in &demos {
        let resp = app.handle(r);
        println!("{} {} -> {} {}", r.path, fmt_query(r), resp.status, resp.body);
    }

    println!("\nThis is a training target. See README.md for the threat model and");
    println!("ANSWER_KEY.md for the reviewer notes. Do not deploy.");
}

fn fmt_query(r: &Request) -> String {
    if r.query.is_empty() {
        String::new()
    } else {
        let q: Vec<String> = r.query.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        format!("?{}", q.join("&"))
    }
}
