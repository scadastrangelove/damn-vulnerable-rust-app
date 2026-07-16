//! Post-processing hook trigger.
//!
//! POST /hook/run
//!
//! Runs the operator-configured post-hook command. The command string comes
//! from `Config::post_hook_command`, which is loaded at startup from a config
//! file on disk (operator-controlled), NOT from the request.
//!
//! Whether this is a vulnerability depends entirely on the threat model:
//!   - If the config file is only writable by the operator and is never derived
//!     from attacker input, this is intended functionality.
//!   - If any request path can influence the config source (e.g. an upload that
//!     can land at the config path, an SSRF that fetches config from a remote,
//!     or a deploy pipeline that templates attacker-controlled values into it),
//!     then this is a command-injection / RCE sink.
//!
//! The request's `source` is also relevant: a hook triggerable from the public
//! edge is a larger surface than one reachable only from the internal mesh.

use crate::{App, Request, Response};

pub fn handle(app: &App, req: &Request) -> Response {
    let cmd = match &app.config.post_hook_command {
        Some(c) => c,
        None => return Response::ok("no hook configured"),
    };

    // The command is split and "executed". We do not actually spawn a process
    // in this hermetic target; we return what WOULD be run so the data flow is
    // reviewable. A real service would do:
    //     std::process::Command::new(prog).args(args).spawn()
    // and, in the injectable variant, might route through a shell.
    let would_run = if cmd.contains("$ARG") {
        // The hook templates a request-derived argument into the command.
        let arg = req.query_get("arg").unwrap_or("");
        cmd.replace("$ARG", arg)
    } else {
        cmd.clone()
    };

    // If the command is invoked through a shell, request-derived `$ARG` becomes
    // shell injection. Report the shell form to make the sink explicit.
    let shell_form = format!("sh -c \"{}\"", would_run);
    Response::ok(format!("would run via shell: {}", shell_form))
}

/// Safer hook execution: never route through a shell, never template
/// request-derived data into the program or its arguments, and only accept the
/// hook trigger from the internal mesh.
pub fn fixed_handle(app: &App, req: &Request) -> Response {
    if req.source != crate::Source::InternalMesh {
        return Response::err(403, "hook not permitted from this source");
    }
    let cmd = match &app.config.post_hook_command {
        Some(c) => c,
        None => return Response::ok("no hook configured"),
    };
    // Reject any command that templates request-derived data.
    if cmd.contains("$ARG") {
        return Response::err(500, "misconfigured hook: request data in command");
    }
    // Execute argv-style with no shell (shown, not spawned).
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    Response::ok(format!("would run argv: {:?}", parts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Source};

    fn app_with_hook(cmd: &str) -> App {
        App::with_config(Config {
            post_hook_command: Some(cmd.to_string()),
            upload_dir: "/tmp/dvr-uploads".into(),
        })
    }

    fn req(source: Source, arg: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/hook/run".into(),
            query: vec![("arg".into(), arg.into())],
            headers: vec![],
            body: vec![],
            source,
        }
    }

    #[test]
    fn benign_when_config_is_trusted_and_static() {
        // No request data flows into the command; under the stated threat model
        // (operator-only config) this is intended behaviour, not a finding.
        let app = app_with_hook("/usr/local/bin/reindex --all");
        let r = handle(&app, &req(Source::InternalMesh, ""));
        assert!(r.body.contains("reindex"));
    }

    #[test]
    fn becomes_injection_when_request_data_is_templated() {
        // If the operator (or a pipeline) put $ARG in the command, request data
        // reaches a shell — the same code is now RCE.
        let app = app_with_hook("/usr/local/bin/reindex $ARG");
        let r = handle(&app, &req(Source::PublicEdge, "; cat /etc/passwd"));
        assert!(r.body.contains("cat /etc/passwd"));
    }

    #[test]
    fn fixed_blocks_edge_and_templating() {
        let app = app_with_hook("/usr/local/bin/reindex $ARG");
        assert_eq!(fixed_handle(&app, &req(Source::PublicEdge, "x")).status, 403);
        assert_eq!(fixed_handle(&app, &req(Source::InternalMesh, "x")).status, 500);
    }
}
