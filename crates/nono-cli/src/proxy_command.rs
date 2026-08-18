//! Standalone `nono proxy` command.
//!
//! Runs the network-filtering / credential-injection proxy as a foreground
//! server, with no sandboxed child. Unlike the `run`/`shell`/`wrap` paths —
//! which start the proxy as a side effect and wire its env vars into the
//! sandboxed process — this command prints the connection details (proxy URL,
//! token, env vars) for the user to point their own tools at, then blocks
//! until Ctrl-C.
//!
//! Proxy settings are loaded from a profile (`--profile`) and extended /
//! overridden by explicit flags, reusing the same config-building machinery as
//! the sandboxed path (`proxy_runtime::build_proxy_config_from_flags`).

use crate::cli::ProxyArgs;
use crate::launch_runtime::{
    CredentialProxyIntent, DomainFilterIntent, EndpointFilterIntent, ProxyLaunchOptions,
    TlsInterceptIntent, UpstreamProxyIntent,
};
use crate::profile;
use crate::proxy_runtime::{apply_tls_intercept_config, build_proxy_config_from_flags};
use colored::Colorize;
use nono::{NonoError, Result};
use tracing::info;

/// Run the standalone proxy server until Ctrl-C.
pub(crate) fn run_proxy(args: ProxyArgs, silent: bool) -> Result<()> {
    // Fail secure: an open proxy (`--no-auth`) must stay on loopback so other
    // hosts can't reach it. Refuse a non-loopback bind without auth.
    if args.no_auth && !args.listen.is_loopback() {
        return Err(NonoError::ConfigParse(format!(
            "--no-auth requires a loopback --listen address (got {}); refusing to start an \
             open proxy reachable from other hosts",
            args.listen
        )));
    }

    let proxy = build_launch_options(&args)?;
    let mut proxy_config = build_proxy_config_from_flags(&proxy)?;

    // Bind + auth settings come from the standalone flags, not the profile.
    proxy_config.bind_addr = args.listen;
    proxy_config.bind_port = args.port;
    proxy_config.require_auth = !args.no_auth;

    // Standalone mode: the session token is the auth boundary (no OS sandbox
    // behind it), so an unauthenticated CONNECT must be rejected with 407
    // rather than tunnelled. Off under `--no-auth`, where there is no token.
    proxy_config.strict_connect_auth = !args.no_auth;

    // Connection ceiling is configurable only on the standalone proxy, where
    // the caller points their own (possibly highly parallel) tooling at it.
    // The sandboxed paths keep the built-in default.
    proxy_config.max_connections = args.max_connections;

    // An explicit `--pass` pins the proxy credential to a caller-chosen value
    // instead of a random per-session token. Reject a blank password so it
    // can't collapse to an effectively-absent secret. `--no-auth` and `--pass`
    // are mutually exclusive at the clap layer.
    if let Some(ref pass) = args.pass {
        if pass.is_empty() {
            return Err(NonoError::ConfigParse(
                "--pass requires a non-empty password".to_string(),
            ));
        }
        proxy_config.session_token = Some(zeroize::Zeroizing::new(pass.clone()));
    }

    // Share the same TLS-intercept wiring as the sandboxed path (sets the
    // intercept CA output directory and merges the parent SSL_CERT_FILE).
    apply_tls_intercept_config(&mut proxy_config, &proxy)?;

    // An explicit `--proxy-ca-cert`/`--proxy-ca-key` pair reuses a caller-owned
    // CA across runs instead of the per-session ephemeral one. Load and
    // validate it eagerly so a bad key/cert fails the command with a clear
    // error, rather than silently downgrading to no interception at server
    // start.
    //
    // ORDERING (load-bearing): this runs *after* `apply_tls_intercept_config`,
    // which is what may install a keychain-managed CA from the profile's
    // `ca_lifecycle=trusted`. Assigning `preloaded_ca` here last is what makes
    // an operator-supplied CA authoritative over any profile-derived one — CLI
    // options always win. Do not hoist this above `apply_tls_intercept_config`.
    // `build_launch_options` additionally suppresses the profile's trust
    // request when `--proxy-ca-cert` is present, so no keychain CA is minted
    // (or authenticated for) only to be replaced here.
    if let (Some(cert_path), Some(key_path)) = (&args.proxy_ca_cert, &args.proxy_ca_key) {
        #[cfg(target_os = "macos")]
        if args.trust_proxy_ca {
            return Err(NonoError::ConfigParse(
                "--proxy-ca-cert cannot be combined with --trust-proxy-ca; the former supplies \
                 its own CA while the latter manages one in the macOS Keychain"
                    .to_string(),
            ));
        }
        proxy_config.preloaded_ca = Some(load_preloaded_ca(cert_path, key_path)?);
    }

    // Build the credential-capture backend (for `cmd://` credential routes) and
    // approval registry from the profile, mirroring `start_proxy_runtime`. Without
    // these, `cmd://` routes fail with "managed credential unavailable" because the
    // proxy has no backend to invoke the capture command.
    let credential_capture_backend = crate::proxy_runtime::build_credential_capture_backend(
        &proxy.credential_capture,
        proxy.session_id.clone(),
    )?;
    let approval_registry =
        crate::approval_runtime::build_proxy_approval_registry(proxy.command_policies.as_ref())?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;

    let handle = rt
        .block_on(async {
            nono_proxy::server::start_with_approval_and_capture_registry(
                proxy_config.clone(),
                approval_registry,
                credential_capture_backend,
            )
            .await
        })
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy: {}", e)))?;

    print_connection_info(&handle, &proxy_config, args.no_auth, silent);

    // Block the foreground until the user interrupts, then shut down cleanly.
    //
    // Nothing consumes the in-memory network audit buffer on the standalone
    // path (only the sandboxed rollback path drains it), so it would fill to
    // its 4096-event cap and then log "audit buffer full" on every subsequent
    // request. Periodically drain it to void to keep the buffer bounded and
    // silent. The events carry no value here — they're collected only for
    // rollback audit recording, which this command does not perform.
    rt.block_on(async {
        let mut drain = tokio::time::interval(std::time::Duration::from_secs(30));
        // The first tick fires immediately; we only care about subsequent ones.
        drain.tick().await;
        loop {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => {
                    if let Err(e) = signal {
                        tracing::warn!("failed to listen for Ctrl-C: {}; shutting down", e);
                    }
                    break;
                }
                _ = drain.tick() => {
                    let _ = handle.drain_audit_events();
                }
            }
        }
    });

    if !silent {
        eprintln!("\n  [nono] Shutting down proxy...");
    }
    handle.shutdown();
    info!("Proxy server stopped");
    Ok(())
}

/// Load a caller-supplied CA from a cert PEM file and a PKCS#8 key PEM file
/// into a [`PreloadedCa`] for cross-run TLS interception.
///
/// Both files are read, recombined into the single key+cert bundle that
/// `split_key_cert_pem` expects, and then round-tripped through
/// [`EphemeralCa::from_existing`] so a mismatched key/cert pair is rejected
/// here with a clear error instead of failing later during TLS handshakes.
/// The parsed CA is discarded; only the validated material is kept.
fn load_preloaded_ca(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<nono_proxy::config::PreloadedCa> {
    let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| {
        NonoError::ConfigParse(format!(
            "failed to read --proxy-ca-cert {}: {e}",
            cert_path.display()
        ))
    })?;
    let key_pem = zeroize::Zeroizing::new(std::fs::read_to_string(key_path).map_err(|e| {
        NonoError::ConfigParse(format!(
            "failed to read --proxy-ca-key {}: {e}",
            key_path.display()
        ))
    })?);

    // `split_key_cert_pem` extracts the PKCS#8 key as DER and returns the cert
    // PEM; the key must come first in the combined bundle.
    let combined = zeroize::Zeroizing::new(format!("{}{}", *key_pem, cert_pem));
    let (key_der, cert_pem) = nono_proxy::tls_intercept::ca::split_key_cert_pem(&combined)
        .map_err(|e| NonoError::ConfigParse(format!("invalid proxy CA material: {e}")))?;

    // Validate key/cert binding up front (also rejects a non-CA certificate).
    nono_proxy::tls_intercept::ca::EphemeralCa::from_existing(&key_der, &cert_pem)
        .map_err(|e| NonoError::ConfigParse(format!("invalid proxy CA material: {e}")))?;

    Ok(nono_proxy::config::PreloadedCa { key_der, cert_pem })
}

/// Merge profile-derived settings (if `--profile` was given) with explicit
/// CLI flags into a `ProxyLaunchOptions`. Profile values come first; CLI flags
/// extend (allow-domains, credentials) or override (network profile, upstream
/// proxy) — matching `proxy_runtime::resolve_effective_proxy_settings`.
fn build_launch_options(args: &ProxyArgs) -> Result<ProxyLaunchOptions> {
    let loaded = match args.profile {
        Some(ref name) => Some(profile::load_profile(name)?),
        None => None,
    };
    let network = loaded.as_ref().map(|p| &p.network);

    let network_profile = args
        .network_profile
        .clone()
        .or_else(|| network.and_then(|n| n.resolved_network_profile().map(String::from)));

    let mut allow_domain: Vec<profile::AllowDomainEntry> =
        network.map(|n| n.allow_domain.clone()).unwrap_or_default();
    allow_domain.extend(
        args.allow_proxy
            .iter()
            .map(|s| crate::proxy_runtime::parse_allow_domain_arg(s)),
    );

    let mut deny_domain: Vec<String> = network.map(|n| n.deny_domain.clone()).unwrap_or_default();
    deny_domain.extend(args.deny_proxy.iter().cloned());

    let mut credentials: Vec<String> = network
        .map(|n| n.resolved_credentials().to_vec())
        .unwrap_or_default();
    for cred in &args.proxy_credential {
        if !credentials.contains(cred) {
            credentials.push(cred.clone());
        }
    }

    let custom_credentials = network
        .map(|n| n.custom_credentials.clone())
        .unwrap_or_default();

    // `cmd://` credential routes resolve through the credential-capture
    // backend, which is built from the profile's top-level `credential_capture`
    // map (and gated by `command_policies` for approvals). Carry both through
    // so the standalone proxy injects captured credentials the same way the
    // sandboxed `run`/`shell`/`wrap` paths do.
    let credential_capture = loaded
        .as_ref()
        .map(|p| p.credential_capture.clone())
        .unwrap_or_default();
    let command_policies = loaded.as_ref().and_then(|p| p.command_policies.clone());

    let upstream_proxy_addr = args
        .external_proxy
        .clone()
        .or_else(|| network.and_then(|n| n.upstream_proxy.clone()));

    let mut upstream_bypass: Vec<String> = network
        .map(|n| n.upstream_bypass.clone())
        .unwrap_or_default();
    upstream_bypass.extend(args.external_proxy_bypass.clone());

    // Bypass entries only make sense with an upstream proxy ("route these
    // direct instead of through the upstream proxy"). Without one they would
    // be silently dropped by the `upstream_proxy_addr.map(...)` below, so
    // reject the combination up front — mirroring `validate_external_proxy_bypass`
    // on the sandboxed path.
    if !upstream_bypass.is_empty() && upstream_proxy_addr.is_none() {
        return Err(NonoError::ConfigParse(
            "--upstream-bypass requires --upstream-proxy \
             (or upstream_proxy in profile network config)"
                .to_string(),
        ));
    }

    // Split allow-domain entries into plain CONNECT-tunnel hosts and
    // endpoint-restricted routes (which require TLS interception), mirroring
    // `prepare_proxy_launch_options` on the sandboxed path.
    let (plain_entries, endpoint_entries): (Vec<_>, Vec<_>) = allow_domain
        .into_iter()
        .partition(|e| !matches!(e, profile::AllowDomainEntry::WithEndpoints { endpoints, .. } if !endpoints.is_empty()));

    let domain_filter =
        if network_profile.is_some() || !plain_entries.is_empty() || !deny_domain.is_empty() {
            Some(DomainFilterIntent {
                network_profile,
                allow_domain: plain_entries,
                deny_domain,
            })
        } else {
            None
        };

    let endpoint_filter = if endpoint_entries.is_empty() {
        None
    } else {
        Some(EndpointFilterIntent {
            routes: endpoint_entries,
        })
    };

    // Per-credential endpoint restrictions from `--allow-endpoint`. The
    // referenced service must also be an active credential; that check happens
    // downstream in `build_proxy_config_from_flags`, shared with the sandboxed
    // path, so an unknown service surfaces the same error.
    let endpoint_restrictions = args
        .allow_endpoint
        .iter()
        .map(|s| crate::proxy_runtime::parse_allow_endpoint_arg(s))
        .collect::<Result<Vec<_>>>()?;

    let credentials_intent = if credentials.is_empty()
        && custom_credentials.is_empty()
        && endpoint_restrictions.is_empty()
    {
        None
    } else {
        Some(CredentialProxyIntent {
            credentials,
            custom_credentials,
            endpoint_restrictions,
        })
    };

    let upstream_proxy = upstream_proxy_addr.map(|address| UpstreamProxyIntent {
        address,
        bypass: upstream_bypass,
    });

    // TLS interception: merge the profile's `network.tls_intercept` block with
    // the CLI flags through the same resolver the sandboxed `run` path uses, so
    // `ca_lifecycle`, `ca_validity`, `leaf_validity`, and `ca_env_vars` are all
    // honoured here too. Building this from flags alone was issue #1667: a
    // profile with `ca_lifecycle: "trusted"` was silently ignored and the proxy
    // signed with a throwaway `CN=nono-session-ca` that nothing trusts.
    let tls_options = crate::proxy_runtime::resolve_profile_tls_intercept_options(
        network.and_then(|n| n.tls_intercept.as_ref()),
        #[cfg(target_os = "macos")]
        args.trust_proxy_ca,
        args.proxy_ca_validity,
    )?;

    // CLI-supplied options always win. An explicit `--proxy-ca-cert` names the
    // exact signing identity to use, so it overrides a profile's
    // `ca_lifecycle=trusted` rather than erroring: drop the profile-derived
    // trust request here so `apply_tls_intercept_config` doesn't install (or
    // prompt for) a keychain CA that `run_proxy` would immediately replace with
    // the supplied one. An explicit `--trust-proxy-ca` alongside
    // `--proxy-ca-cert` is still a flag-vs-flag contradiction and is rejected
    // in `run_proxy`.
    #[cfg(target_os = "macos")]
    let trust_proxy_ca = tls_options.trust_proxy_ca && args.proxy_ca_cert.is_none();

    #[cfg(target_os = "macos")]
    let tls_intercept = if trust_proxy_ca
        || tls_options.ca_validity.is_some()
        || !tls_options.ca_env_vars.is_empty()
    {
        Some(TlsInterceptIntent {
            trust_proxy_ca,
            ca_validity: tls_options.ca_validity,
            ca_env_vars: tls_options.ca_env_vars.clone(),
        })
    } else {
        None
    };
    #[cfg(not(target_os = "macos"))]
    let tls_intercept = if tls_options.ca_validity.is_some() || !tls_options.ca_env_vars.is_empty()
    {
        Some(TlsInterceptIntent {
            ca_validity: tls_options.ca_validity,
            ca_env_vars: tls_options.ca_env_vars.clone(),
        })
    } else {
        None
    };

    // Enable HTTP/2 to upstreams when requested via the CLI flag or the
    // profile's `network.allow_http2`, mirroring the sandboxed `run` path.
    let enable_h2 = args.allow_http2 || network.map(|n| n.allow_http2).unwrap_or(false);

    Ok(ProxyLaunchOptions {
        domain_filter,
        endpoint_filter,
        credentials: credentials_intent,
        upstream_proxy,
        tls_intercept,
        // Leaf validity rides alongside `tls_intercept` rather than inside it
        // (matching `prepare_proxy_launch_options`), so carry it through
        // explicitly or the profile's `leaf_validity` would be dropped here.
        proxy_leaf_validity: tls_options.leaf_validity,
        command_policies,
        credential_capture,
        session_id: crate::session::generate_session_id(),
        enable_h2,
        ..ProxyLaunchOptions::default()
    })
}

/// Print the proxy URL, env vars, and per-route diagnostics to stdout.
fn print_connection_info(
    handle: &nono_proxy::server::ProxyHandle,
    config: &nono_proxy::config::ProxyConfig,
    no_auth: bool,
    silent: bool,
) {
    let addr = config.bind_addr;
    let port = handle.port;

    if silent {
        return;
    }

    println!();
    println!("  {} {}:{}", "nono proxy listening on".bold(), addr, port);

    if no_auth {
        println!(
            "  {}",
            "auth disabled (--no-auth): any local process can use this proxy".yellow()
        );
        println!("  proxy URL: http://{}:{}", addr, port);
    } else {
        // The token-bearing URL works with standard clients (Basic auth via
        // userinfo). Surface it directly plus the raw token for Bearer clients.
        println!(
            "  proxy URL: {}",
            format!("http://nono:{}@{}:{}", *handle.token, addr, port).cyan()
        );
        println!("  token:     {}", (*handle.token).dimmed());
        println!();
        println!(
            "  export HTTPS_PROXY=http://nono:{}@{}:{}",
            *handle.token, addr, port
        );
        println!(
            "  export HTTP_PROXY=http://nono:{}@{}:{}",
            *handle.token, addr, port
        );
    }

    let route_rows = handle.route_diagnostics(config);
    if !route_rows.is_empty() {
        println!();
        println!("  {}", "routes:".bold());
        for summary in &route_rows {
            println!("    {}", summary);
        }
    }

    if let Some(ca_path) = handle.intercept_ca_path() {
        println!();
        println!("  TLS interception trust bundle: {}", ca_path.display());
    }

    println!();
    println!("  {}", "Press Ctrl-C to stop.".dimmed());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use clap::Parser;

    /// `ProxyArgs` fields bind to `NONO_*` env vars (e.g. `NONO_PROFILE`),
    /// which would otherwise leak from the surrounding environment and make
    /// these tests non-hermetic. Clear them for the duration of the test.
    const PROXY_ENV_VARS: &[&str] = &[
        "NONO_PROFILE",
        "NONO_NETWORK_PROFILE",
        "NONO_ALLOW_DOMAIN",
        "NONO_UPSTREAM_PROXY",
        "NONO_UPSTREAM_BYPASS",
        "NONO_PROXY_CA_VALIDITY",
        "NONO_PROXY_CA_CERT",
        "NONO_PROXY_CA_KEY",
        "NONO_TRUST_PROXY_CA",
        "NONO_CREDENTIAL",
        "NONO_PROXY_MAX_CONNECTIONS",
    ];

    fn cleared_env() -> EnvVarGuard {
        let pairs: Vec<(&'static str, &str)> = PROXY_ENV_VARS.iter().map(|k| (*k, "")).collect();
        let guard = EnvVarGuard::set_all(&pairs);
        for key in PROXY_ENV_VARS {
            guard.remove(key);
        }
        guard
    }

    fn parse_args(extra: &[&str]) -> ProxyArgs {
        let mut argv = vec!["proxy"];
        argv.extend_from_slice(extra);
        ProxyArgs::try_parse_from(argv).expect("parse proxy args")
    }

    #[test]
    fn max_connections_defaults_to_256() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&[]);
        assert_eq!(args.max_connections, 256);
    }

    #[test]
    fn max_connections_override_parses() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&["--max-connections", "4096"]);
        assert_eq!(args.max_connections, 4096);
    }

    #[test]
    fn upstream_bypass_without_upstream_proxy_is_rejected() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&["--upstream-bypass", "example.com"]);
        let err = build_launch_options(&args).expect_err("bypass without upstream must fail");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    #[test]
    fn upstream_bypass_with_upstream_proxy_is_accepted() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&[
            "--upstream-proxy",
            "127.0.0.1:8080",
            "--upstream-bypass",
            "example.com",
        ]);
        let opts = build_launch_options(&args).expect("bypass with upstream is valid");
        let upstream = opts.upstream_proxy.expect("upstream proxy carried through");
        assert_eq!(upstream.address, "127.0.0.1:8080");
        assert_eq!(upstream.bypass, vec!["example.com".to_string()]);
    }

    #[test]
    fn upstream_proxy_alone_carries_through() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&["--upstream-proxy", "127.0.0.1:8080"]);
        let opts = build_launch_options(&args).expect("upstream alone is valid");
        let upstream = opts.upstream_proxy.expect("upstream proxy carried through");
        assert_eq!(upstream.address, "127.0.0.1:8080");
        assert!(upstream.bypass.is_empty());
    }

    #[test]
    fn no_upstream_flags_yields_no_upstream_proxy() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&[]);
        let opts = build_launch_options(&args).expect("empty args are valid");
        assert!(opts.upstream_proxy.is_none());
    }

    #[test]
    fn no_profile_yields_empty_credential_capture() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&[]);
        let opts = build_launch_options(&args).expect("empty args are valid");
        assert!(opts.credential_capture.is_empty());
        assert!(opts.command_policies.is_none());
        // A session id is always minted so the capture backend can scope caches.
        assert!(!opts.session_id.is_empty());
    }

    #[test]
    fn enable_h2_defaults_off() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&[]);
        let opts = build_launch_options(&args).expect("empty args are valid");
        assert!(!opts.enable_h2);
    }

    #[test]
    fn allow_http2_flag_enables_h2() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&["--allow-http2"]);
        let opts = build_launch_options(&args).expect("flag-only args are valid");
        assert!(opts.enable_h2);
    }

    #[test]
    fn profile_allow_http2_enables_h2() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let dir = tempfile::tempdir().expect("tmpdir");
        let profile_path = dir.path().join("h2.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "h2-test" },
                "network": { "allow_http2": true }
            }"#,
        )
        .expect("write profile");

        let args = parse_args(&["--profile", profile_path.to_str().expect("valid utf8")]);
        let opts = build_launch_options(&args).expect("profile with allow_http2 is valid");
        assert!(opts.enable_h2);
    }

    #[test]
    fn profile_credential_capture_carries_through() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let dir = tempfile::tempdir().expect("tmpdir");
        let profile_path = dir.path().join("capture.json");
        std::fs::write(
            &profile_path,
            r#"{
                "meta": { "name": "capture-test" },
                "credential_capture": {
                    "github": {
                        "command": ["true", "auth", "github"],
                        "cache_path_regex": "^/(?:repos/|orgs/|raw/)?([^/]+)",
                        "timeout_secs": 60
                    }
                }
            }"#,
        )
        .expect("write profile");

        let args = parse_args(&["--profile", profile_path.to_str().expect("valid utf8")]);
        let opts = build_launch_options(&args).expect("profile with capture is valid");
        let entry = opts
            .credential_capture
            .get("github")
            .expect("github capture entry carried through");
        assert_eq!(entry.command, vec!["true", "auth", "github"]);
    }

    #[test]
    fn allow_endpoint_populates_credential_restrictions() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&[
            "--credential",
            "github",
            "--allow-endpoint",
            "github:GET:/repos/*/issues",
        ]);
        let opts = build_launch_options(&args).expect("allow-endpoint with credential is valid");
        let creds = opts.credentials.expect("credential intent present");
        assert_eq!(creds.endpoint_restrictions.len(), 1);
        let (service, rule) = &creds.endpoint_restrictions[0];
        assert_eq!(service, "github");
        assert_eq!(rule.method, "GET");
        assert_eq!(rule.path, "/repos/*/issues");
    }

    #[test]
    fn allow_endpoint_alone_yields_credential_intent() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        // Even without --credential, an endpoint restriction produces a
        // credential intent so the downstream "service not found" check fires.
        let args = parse_args(&["--allow-endpoint", "github:GET:/repos/*/issues"]);
        let opts = build_launch_options(&args).expect("allow-endpoint alone parses");
        assert!(opts.credentials.is_some());
    }

    #[test]
    fn malformed_allow_endpoint_is_rejected() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let args = parse_args(&["--allow-endpoint", "github:GET"]);
        let err = build_launch_options(&args).expect_err("missing path must fail");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    /// Write a fresh, self-consistent CA key+cert pair to two temp files and
    /// return their paths (plus the tempdir, which must outlive them).
    fn write_ca_pair() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let ca = nono_proxy::tls_intercept::ca::EphemeralCa::generate().expect("generate CA");
        let dir = tempfile::tempdir().expect("tmpdir");
        let cert_path = dir.path().join("ca.crt");
        let key_path = dir.path().join("ca.key");
        std::fs::write(&cert_path, ca.cert_pem()).expect("write cert");
        std::fs::write(&key_path, &*ca.key_pem()).expect("write key");
        (dir, cert_path, key_path)
    }

    #[test]
    fn load_preloaded_ca_accepts_matching_pair() {
        let (_dir, cert_path, key_path) = write_ca_pair();
        let preloaded =
            load_preloaded_ca(&cert_path, &key_path).expect("matching CA pair must load");
        assert!(!preloaded.key_der.is_empty());
        assert!(preloaded.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn load_preloaded_ca_rejects_mismatched_key() {
        // Cert from one CA, key from another: from_existing must reject the
        // binding rather than silently accept it.
        let (_dir_a, cert_path, _key_a) = write_ca_pair();
        let (_dir_b, _cert_b, key_path) = write_ca_pair();
        let err = load_preloaded_ca(&cert_path, &key_path)
            .expect_err("mismatched key/cert must be rejected");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    #[test]
    fn load_preloaded_ca_rejects_missing_file() {
        let (_dir, cert_path, key_path) = write_ca_pair();
        std::fs::remove_file(&key_path).expect("remove key");
        let err =
            load_preloaded_ca(&cert_path, &key_path).expect_err("missing key file must error");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    /// Write a profile with the given `network.tls_intercept` JSON body and
    /// return its path (plus the tempdir, which must outlive it).
    fn profile_with_tls_intercept(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("tls.json");
        std::fs::write(
            &path,
            format!(
                r#"{{
                    "meta": {{ "name": "tls-test" }},
                    "network": {{
                        "allow_domain": ["example.com"],
                        "tls_intercept": {body}
                    }}
                }}"#
            ),
        )
        .expect("write profile");
        (dir, path)
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn profile_ca_lifecycle_trusted_is_honoured() {
        // Regression (issue #1667): `nono proxy --profile <p>` ignored the
        // profile's `tls_intercept.ca_lifecycle`, so a profile asking for the
        // keychain-trusted CA still got a throwaway `CN=nono-session-ca`.
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let (_dir, profile_path) =
            profile_with_tls_intercept(r#"{ "ca_lifecycle": "trusted", "ca_validity": "365d" }"#);
        let args = parse_args(&["--profile", profile_path.to_str().expect("valid utf8")]);
        let opts = build_launch_options(&args).expect("trusted profile is valid");
        let tls = opts
            .tls_intercept
            .expect("profile ca_lifecycle=trusted must produce a TLS intercept intent");
        assert!(
            tls.trust_proxy_ca,
            "ca_lifecycle=trusted must set trust_proxy_ca without needing --trust-proxy-ca"
        );
        assert_eq!(
            tls.ca_validity,
            Some(std::time::Duration::from_secs(365 * 24 * 60 * 60)),
            "profile ca_validity must be carried through"
        );
    }

    #[test]
    fn profile_ca_lifecycle_session_stays_untrusted() {
        // The opposite direction: an explicit `session` lifecycle (and the
        // default) must not opt into the keychain CA.
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let (_dir, profile_path) = profile_with_tls_intercept(r#"{ "ca_lifecycle": "session" }"#);
        let args = parse_args(&["--profile", profile_path.to_str().expect("valid utf8")]);
        let opts = build_launch_options(&args).expect("session profile is valid");
        #[cfg(target_os = "macos")]
        assert!(
            opts.tls_intercept.is_none_or(|tls| !tls.trust_proxy_ca),
            "ca_lifecycle=session must not request the trusted CA"
        );
        #[cfg(not(target_os = "macos"))]
        assert!(opts.tls_intercept.is_none());
    }

    #[test]
    fn profile_leaf_validity_is_carried_through() {
        // `leaf_validity` rides outside `TlsInterceptIntent`, so it needs its
        // own wiring; without it the profile value was dropped.
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let (_dir, profile_path) = profile_with_tls_intercept(r#"{ "leaf_validity": "15m" }"#);
        let args = parse_args(&["--profile", profile_path.to_str().expect("valid utf8")]);
        let opts = build_launch_options(&args).expect("leaf_validity profile is valid");
        assert_eq!(
            opts.proxy_leaf_validity,
            Some(std::time::Duration::from_secs(15 * 60)),
            "profile leaf_validity must reach the proxy config"
        );
    }

    #[test]
    fn profile_ca_env_vars_are_carried_through() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let (_dir, profile_path) =
            profile_with_tls_intercept(r#"{ "ca_env_vars": ["REQUESTS_CA_BUNDLE"] }"#);
        let args = parse_args(&["--profile", profile_path.to_str().expect("valid utf8")]);
        let opts = build_launch_options(&args).expect("ca_env_vars profile is valid");
        let tls = opts
            .tls_intercept
            .expect("ca_env_vars alone must produce a TLS intercept intent");
        assert_eq!(tls.ca_env_vars, vec!["REQUESTS_CA_BUNDLE".to_string()]);
    }

    #[test]
    fn flag_ca_validity_overrides_profile() {
        // Precedence: an explicit flag beats the profile, matching the rest of
        // the CLI and the sandboxed `run` path.
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let (_dir, profile_path) = profile_with_tls_intercept(r#"{ "ca_validity": "365d" }"#);
        let args = parse_args(&[
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--proxy-ca-validity",
            "7",
        ]);
        let opts = build_launch_options(&args).expect("flag override is valid");
        let tls = opts.tls_intercept.expect("intent present");
        assert_eq!(
            tls.ca_validity,
            Some(std::time::Duration::from_secs(7 * 24 * 60 * 60)),
            "--proxy-ca-validity must win over the profile value"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn trust_flag_conflicting_with_session_profile_is_rejected() {
        // `--trust-proxy-ca` against an explicit `ca_lifecycle=session` is a
        // contradiction; the shared resolver must reject it here exactly as it
        // does on the sandboxed path rather than silently picking a side.
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let (_dir, profile_path) = profile_with_tls_intercept(r#"{ "ca_lifecycle": "session" }"#);
        let args = parse_args(&[
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--trust-proxy-ca",
        ]);
        let err = build_launch_options(&args).expect_err("conflicting trust request must fail");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn profile_ca_lifecycle_trusted_is_rejected_off_macos() {
        // The keychain CA is macOS-only; asking for it elsewhere must fail
        // loudly instead of silently downgrading to a session CA.
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let (_dir, profile_path) = profile_with_tls_intercept(r#"{ "ca_lifecycle": "trusted" }"#);
        let args = parse_args(&["--profile", profile_path.to_str().expect("valid utf8")]);
        let err = build_launch_options(&args).expect_err("trusted off macOS must fail");
        assert!(matches!(err, NonoError::ConfigParse(_)), "got {err:?}");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn custom_ca_flag_overrides_profile_trusted_ca() {
        // CLI-supplied options always win: `--proxy-ca-cert` names the exact
        // signing identity, so it overrides the profile's
        // `ca_lifecycle=trusted` instead of erroring. The profile's trust
        // request must be suppressed so no keychain CA is minted (or
        // authenticated for) only for `run_proxy` to replace it.
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let (_ca_dir, cert_path, key_path) = write_ca_pair();
        let (_dir, profile_path) = profile_with_tls_intercept(r#"{ "ca_lifecycle": "trusted" }"#);
        let args = parse_args(&[
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--proxy-ca-cert",
            cert_path.to_str().expect("valid utf8"),
            "--proxy-ca-key",
            key_path.to_str().expect("valid utf8"),
        ]);
        let opts = build_launch_options(&args).expect("custom CA overrides the profile");
        assert!(
            opts.tls_intercept.is_none_or(|tls| !tls.trust_proxy_ca),
            "--proxy-ca-cert must suppress the profile's keychain-CA request"
        );
    }

    #[test]
    fn custom_ca_is_used_verbatim() {
        // A caller-supplied CA must survive profile resolution: the material
        // `run_proxy` installs is exactly the supplied certificate.
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let (_ca_dir, cert_path, key_path) = write_ca_pair();
        let (_dir, profile_path) = profile_with_tls_intercept(r#"{ "leaf_validity": "15m" }"#);
        let args = parse_args(&[
            "--profile",
            profile_path.to_str().expect("valid utf8"),
            "--proxy-ca-cert",
            cert_path.to_str().expect("valid utf8"),
            "--proxy-ca-key",
            key_path.to_str().expect("valid utf8"),
        ]);
        build_launch_options(&args).expect("custom CA with a profile is valid");

        let expected = std::fs::read_to_string(&cert_path).expect("read cert");
        let preloaded = load_preloaded_ca(&cert_path, &key_path).expect("supplied CA must load");
        assert_eq!(
            preloaded.cert_pem.trim(),
            expected.trim(),
            "the supplied CA certificate must be used verbatim"
        );
    }

    #[test]
    fn proxy_ca_cert_requires_key() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        // clap enforces the mutual `requires`: cert without key is a parse error.
        let res = ProxyArgs::try_parse_from(["proxy", "--proxy-ca-cert", "/tmp/ca.crt"]);
        assert!(res.is_err(), "cert without key must fail to parse");
    }

    #[test]
    fn proxy_ca_cert_conflicts_with_validity() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        let _env = cleared_env();
        let res = ProxyArgs::try_parse_from([
            "proxy",
            "--proxy-ca-cert",
            "/tmp/ca.crt",
            "--proxy-ca-key",
            "/tmp/ca.key",
            "--proxy-ca-validity",
            "30",
        ]);
        assert!(res.is_err(), "supplying a CA and a validity must conflict");
    }
}
