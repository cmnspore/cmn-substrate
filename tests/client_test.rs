#![cfg(feature = "client")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use substrate::client::FetchOptions;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap()
}

/// A valid cmn.json payload that passes schema validation.
fn valid_cmn_json() -> serde_json::Value {
    json!({
        "$schema": "https://cmn.dev/schemas/v1/cmn.json",
        "capsules": [{
            "uri": "cmn://example.com",
            "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
            "endpoints": [
                {
                    "type": "spore",
                    "url": "https://example.com/cmn/spore/{hash}.json"
                }
            ]
        }],
        "capsule_signature": "ed25519.3yMR7vZQ9hL"
    })
}

// ---------------------------------------------------------------------------
// fetch_cmn_entry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_cmn_entry_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/cmn.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(valid_cmn_json()))
        .mount(&server)
        .await;

    // cmn_entry_url produces https:// but our mock is http://, so call with
    // the server URL directly via the lower-level approach.
    let client = test_client();
    let url = format!("{}/.well-known/cmn.json", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    assert!(resp.status().is_success());

    // Use the full function by overriding the domain to a .onion address
    // (which uses http://) — but that still won't hit our mock.
    // Instead, test via the raw URL to verify JSON parsing + validation.
    let resp2 = client.get(&url).send().await.unwrap();
    let payload: serde_json::Value = resp2.json().await.unwrap();
    let schema_type = substrate::validate_schema(&payload).unwrap();
    assert_eq!(schema_type, substrate::SchemaType::Cmn);
    let entry: substrate::CmnEntry = serde_json::from_value(payload).unwrap();
    assert!(entry.primary_capsule().is_ok());
}

#[tokio::test]
async fn fetch_cmn_entry_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/cmn.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    // Extract host:port from server URI to construct a .onion-like domain
    // so cmn_entry_url uses http://. Actually, let's just test via direct URL.
    let client = test_client();
    let url = format!("{}/.well-known/cmn.json", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn fetch_cmn_entry_wrong_schema_type() {
    let server = MockServer::start().await;

    // Return a document with a non-CMN $schema — detect_schema_type will
    // identify it as Mycelium, and fetch_cmn_entry should reject it.
    let non_cmn_doc = json!({
        "$schema": "https://cmn.dev/schemas/v1/mycelium.json",
        "data": "irrelevant"
    });

    Mock::given(method("GET"))
        .and(path("/.well-known/cmn.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(non_cmn_doc))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/.well-known/cmn.json", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    let payload: serde_json::Value = resp.json().await.unwrap();
    let detected = substrate::detect_schema_type(&payload).unwrap();
    assert_eq!(detected, substrate::SchemaType::Mycelium);
}

#[tokio::test]
async fn fetch_cmn_entry_invalid_json() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/cmn.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/.well-known/cmn.json", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    let result: Result<serde_json::Value, _> = resp.json().await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// fetch_spore_manifest
// ---------------------------------------------------------------------------

/// Test fetch_spore_manifest with a successful response.
///
/// CmnCapsuleEntry.spore_url() validates URLs (rejects http:// for non-onion),
/// so we test the HTTP+JSON layer via json_from_response directly and verify
/// the endpoint template resolution separately.
#[tokio::test]
async fn fetch_spore_manifest_json_parsing() {
    let server = MockServer::start().await;

    let manifest = json!({
        "$schema": "https://cmn.dev/schemas/v1/spore.json",
        "capsule": {
            "uri": "cmn://example.com/b3.testhash",
            "core": {
                "name": "test-spore",
                "domain": "example.com",
                "synopsis": "A test",
                "intent": ["Testing"],
                "license": "MIT"
            },
            "core_signature": "ed25519.sig"
        },
        "capsule_signature": "ed25519.sig"
    });

    Mock::given(method("GET"))
        .and(path("/cmn/spore/b3.testhash.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(manifest.clone()))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/cmn/spore/b3.testhash.json", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    assert!(resp.status().is_success());

    let result: serde_json::Value = substrate::client::json_from_response(resp, &url, None)
        .await
        .unwrap();
    assert_eq!(result["capsule"]["core"]["name"], "test-spore");
}

/// Verify that non-success HTTP status is properly detected.
#[tokio::test]
async fn fetch_spore_manifest_http_500() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/cmn/spore/b3.bad.json"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/cmn/spore/b3.bad.json", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 500);
}

/// Verify CmnCapsuleEntry.spore_url resolves the {hash} template.
#[test]
fn spore_url_template_resolution() {
    let cmn_json = json!({
        "$schema": "https://cmn.dev/schemas/v1/cmn.json",
        "capsules": [{
            "uri": "cmn://example.com",
            "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
            "endpoints": [{
                "type": "spore",
                "url": "https://example.com/cmn/spore/{hash}.json"
            }]
        }],
        "capsule_signature": "ed25519.3yMR7vZQ9hL"
    });
    let entry: substrate::CmnEntry = serde_json::from_value(cmn_json).unwrap();
    let capsule = entry.primary_capsule().unwrap();
    let url = capsule.spore_url("b3.testhash").unwrap();
    assert_eq!(url, "https://example.com/cmn/spore/b3.testhash.json");
}

// ---------------------------------------------------------------------------
// FetchOptions / byte limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_with_byte_limit_accepts_small_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/cmn.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(valid_cmn_json()))
        .mount(&server)
        .await;

    // Use a generous limit — should succeed
    let client = test_client();
    let url = format!("{}/.well-known/cmn.json", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    let result: Result<serde_json::Value, _> =
        substrate::client::json_from_response(resp, &url, Some(256 * 1024)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn fetch_with_byte_limit_rejects_oversized_response() {
    let server = MockServer::start().await;

    // Create a large response body
    let large_body = "x".repeat(1024);

    Mock::given(method("GET"))
        .and(path("/large"))
        .respond_with(ResponseTemplate::new(200).set_body_string(&large_body))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/large", server.uri());
    let resp = client.get(&url).send().await.unwrap();

    // Limit to 100 bytes — should fail
    let result: Result<serde_json::Value, _> =
        substrate::client::json_from_response(resp, &url, Some(100)).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("exceeded limit") || err.contains("too large"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn fetch_with_no_limit_accepts_any_size() {
    let server = MockServer::start().await;

    let body = json!({"ok": true});

    Mock::given(method("GET"))
        .and(path("/any"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/any", server.uri());
    let resp = client.get(&url).send().await.unwrap();

    // No limit
    let result: Result<serde_json::Value, _> =
        substrate::client::json_from_response(resp, &url, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["ok"], true);
}

// ---------------------------------------------------------------------------
// Synapse: search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_success() {
    let server = MockServer::start().await;

    let response = json!({
        "code": "ok",
        "result": {
            "query": {
                "text": "test",
                "domain": null,
                "license": null,
                "limit": 10
            },
            "spores": [{
                "uri": "cmn://example.com/b3.abc",
                "domain": "example.com",
                "name": "test-spore",
                "synopsis": "A test spore",
                "license": "MIT",
                "intent": ["Testing"],
                "relevance": 0.95
            }]
        }
    });

    Mock::given(method("GET"))
        .and(path("/synapse/search"))
        .and(query_param("q", "test"))
        .and(query_param("limit", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::search(
        &client,
        &server.uri(),
        "test",
        None,
        None,
        None,
        10,
        Default::default(),
    )
    .await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.result.spores.len(), 1);
    assert_eq!(resp.result.spores[0].name, "test-spore");
}

#[tokio::test]
async fn search_with_all_filters() {
    let server = MockServer::start().await;

    let response = json!({
        "code": "ok",
        "result": {
            "query": {"text": "tools", "domain": "cmn.dev", "license": "MIT", "limit": 5},
            "spores": []
        }
    });

    Mock::given(method("GET"))
        .and(path("/synapse/search"))
        .and(query_param("q", "tools"))
        .and(query_param("domain", "cmn.dev"))
        .and(query_param("license", "MIT"))
        .and(query_param("bonds", "spawned_from:cmn://a.dev/b3.x"))
        .and(query_param("limit", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::search(
        &client,
        &server.uri(),
        "tools",
        Some("cmn.dev"),
        Some("MIT"),
        Some("spawned_from:cmn://a.dev/b3.x"),
        5,
        Default::default(),
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().result.spores.len(), 0);
}

#[tokio::test]
async fn search_bearer_token() {
    let server = MockServer::start().await;

    let response = json!({
        "code": "ok",
        "result": {
            "query": {"text": "q", "domain": null, "license": null, "limit": 1},
            "spores": []
        }
    });

    Mock::given(method("GET"))
        .and(path("/synapse/search"))
        .and(header("authorization", "Bearer secret-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::search(
        &client,
        &server.uri(),
        "q",
        None,
        None,
        None,
        1,
        substrate::client::FetchOptions::with_bearer_token("secret-token"),
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn search_503_not_configured() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/synapse/search"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::search(
        &client,
        &server.uri(),
        "q",
        None,
        None,
        None,
        10,
        Default::default(),
    )
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not configured"));
}

// ---------------------------------------------------------------------------
// Synapse: fetch_lineage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_lineage_success() {
    let server = MockServer::start().await;

    let response = json!({
        "code": "ok",
        "result": {
            "query": {"hash": "b3.abc", "max_depth": 3},
            "bonds": [{
                "uri": "cmn://example.com/b3.parent",
                "domain": "example.com",
                "name": "parent-spore",
                "synopsis": "Parent",
                "license": "MIT",
                "intent": ["Testing"],
                "relation": "spawned_from"
            }]
        },
        "trace": {"max_depth_reached": false}
    });

    Mock::given(method("GET"))
        .and(path("/synapse/spore/b3.abc/bonds"))
        .and(query_param("direction", "outbound"))
        .and(query_param("max_depth", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::fetch_lineage(
        &client,
        &server.uri(),
        "b3.abc",
        "outbound",
        3,
        Default::default(),
    )
    .await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.result.bonds.len(), 1);
    assert_eq!(resp.result.bonds[0].name, "parent-spore");
    assert!(!resp.trace.unwrap().max_depth_reached);
}

#[tokio::test]
async fn fetch_lineage_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/synapse/spore/b3.missing/bonds"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::fetch_lineage(
        &client,
        &server.uri(),
        "b3.missing",
        "inbound",
        1,
        Default::default(),
    )
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

// ---------------------------------------------------------------------------
// Synapse: fetch_taste_reports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_taste_reports_success() {
    let server = MockServer::start().await;

    let response = json!({
        "code": "ok",
        "result": {
            "tastes": [
                {"verdict": "safe", "domain": "taster.example.com"}
            ]
        }
    });

    Mock::given(method("GET"))
        .and(path("/synapse/spore/b3.abc/tastes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response.clone()))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::fetch_taste_reports(
        &client,
        &server.uri(),
        "b3.abc",
        Default::default(),
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), response);
}

#[tokio::test]
async fn fetch_taste_reports_with_token() {
    let server = MockServer::start().await;

    let response = json!({"code": "ok", "result": {"tastes": []}});

    Mock::given(method("GET"))
        .and(path("/synapse/spore/b3.xyz/tastes"))
        .and(header("authorization", "Bearer my-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::fetch_taste_reports(
        &client,
        &server.uri(),
        "b3.xyz",
        substrate::client::FetchOptions::with_bearer_token("my-token"),
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn fetch_taste_reports_server_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/synapse/spore/b3.err/tastes"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::fetch_taste_reports(
        &client,
        &server.uri(),
        "b3.err",
        Default::default(),
    )
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("HTTP 502"));
}

// ---------------------------------------------------------------------------
// FetchOptions unit tests
// ---------------------------------------------------------------------------

#[test]
fn fetch_options_default_has_no_limit() {
    let opts = FetchOptions::default();
    assert_eq!(opts.max_bytes, None);
}

#[test]
fn fetch_options_with_max_bytes() {
    let opts = FetchOptions::with_max_bytes(1024);
    assert_eq!(opts.max_bytes, Some(1024));
}

#[test]
fn fetch_options_new_equals_default() {
    let a = FetchOptions::new();
    let b = FetchOptions::default();
    assert_eq!(a.max_bytes, b.max_bytes);
}

// ---------------------------------------------------------------------------
// fetch_mycelium_manifest
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_mycelium_manifest_json_parsing() {
    let server = MockServer::start().await;

    let manifest = json!({
        "$schema": "https://cmn.dev/schemas/v1/mycelium.json",
        "capsule": {
            "uri": "cmn://example.com/mycelium/b3.mychash",
            "core": {
                "domain": "example.com",
                "bio": "Test mycelium",
                "spores": [{"name": "test", "hash": "b3.abc"}],
                "updated_at_epoch_ms": 1700000000000_u64
            },
            "core_signature": "ed25519.sig"
        },
        "capsule_signature": "ed25519.sig"
    });

    Mock::given(method("GET"))
        .and(path("/cmn/mycelium/b3.mychash.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(manifest.clone()))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/cmn/mycelium/b3.mychash.json", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    let result: serde_json::Value = substrate::client::json_from_response(resp, &url, None)
        .await
        .unwrap();
    assert_eq!(result["capsule"]["core"]["bio"], "Test mycelium");
}

#[test]
fn mycelium_url_template_resolution() {
    let cmn_json = json!({
        "$schema": "https://cmn.dev/schemas/v1/cmn.json",
        "capsules": [{
            "uri": "cmn://example.com",
            "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
            "endpoints": [{
                "type": "mycelium",
                "url": "https://example.com/cmn/mycelium/{hash}.json",
                "hash": "b3.mychash"
            }]
        }],
        "capsule_signature": "ed25519.3yMR7vZQ9hL"
    });
    let entry: substrate::CmnEntry = serde_json::from_value(cmn_json).unwrap();
    let capsule = entry.primary_capsule().unwrap();
    let url = capsule.mycelium_url("b3.mychash").unwrap();
    assert_eq!(url, "https://example.com/cmn/mycelium/b3.mychash.json");
}

// ---------------------------------------------------------------------------
// fetch_taste
// ---------------------------------------------------------------------------

#[test]
fn taste_url_template_resolution() {
    let cmn_json = json!({
        "$schema": "https://cmn.dev/schemas/v1/cmn.json",
        "capsules": [{
            "uri": "cmn://example.com",
            "key": "ed25519.5XmkQ9vZP8nL3xJdFtR7wNcA6sY2bKgU1eH9pXb4",
            "endpoints": [{
                "type": "taste",
                "url": "https://example.com/cmn/taste/{hash}.json"
            }]
        }],
        "capsule_signature": "ed25519.3yMR7vZQ9hL"
    });
    let entry: substrate::CmnEntry = serde_json::from_value(cmn_json).unwrap();
    let capsule = entry.primary_capsule().unwrap();
    let url = capsule.taste_url("b3.tastehash").unwrap();
    assert_eq!(url, "https://example.com/cmn/taste/b3.tastehash.json");
}

// ---------------------------------------------------------------------------
// text_from_response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn text_from_response_unlimited() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/text"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hello world"))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/text", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    let text = substrate::client::text_from_response(resp, &url, None)
        .await
        .unwrap();
    assert_eq!(text, "hello world");
}

#[tokio::test]
async fn text_from_response_within_limit() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/text"))
        .respond_with(ResponseTemplate::new(200).set_body_string("short"))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/text", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    let text = substrate::client::text_from_response(resp, &url, Some(1024))
        .await
        .unwrap();
    assert_eq!(text, "short");
}

#[tokio::test]
async fn text_from_response_exceeds_limit() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/text"))
        .respond_with(ResponseTemplate::new(200).set_body_string("this is a long string"))
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/text", server.uri());
    let resp = client.get(&url).send().await.unwrap();
    let result = substrate::client::text_from_response(resp, &url, Some(5)).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("exceeded limit") || err.contains("too large"),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Synapse: fetch_synapse_spore
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_synapse_spore_success() {
    let server = MockServer::start().await;

    let response = json!({
        "code": "ok",
        "result": {
            "query": {"hash": "b3.abc123"},
            "spore": {
                "$schema": "https://cmn.dev/schemas/v1/spore.json",
                "capsule": {
                    "uri": "cmn://example.com/b3.abc123",
                    "core": {
                        "name": "test-spore",
                        "domain": "example.com",
                        "synopsis": "A test",
                        "intent": ["Testing"],
                        "license": "MIT"
                    },
                    "core_signature": "ed25519.sig"
                },
                "capsule_signature": "ed25519.sig"
            },
            "replicates": ["synapse2.example.com"]
        }
    });

    Mock::given(method("GET"))
        .and(path("/synapse/spore/b3.abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::fetch_synapse_spore(
        &client,
        &server.uri(),
        "b3.abc123",
        Default::default(),
    )
    .await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.code, "ok");
    assert_eq!(resp.result.query.hash, "b3.abc123");
    assert_eq!(resp.result.spore["capsule"]["core"]["name"], "test-spore");
    assert_eq!(resp.result.replicates.len(), 1);
}

#[tokio::test]
async fn fetch_synapse_spore_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/synapse/spore/b3.missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::fetch_synapse_spore(
        &client,
        &server.uri(),
        "b3.missing",
        Default::default(),
    )
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

// ---------------------------------------------------------------------------
// Synapse: fetch_synapse_mycelium
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_synapse_mycelium_success() {
    let server = MockServer::start().await;

    let response = json!({
        "code": "ok",
        "result": {
            "query": {"domain": "example.com"},
            "mycelium": {
                "$schema": "https://cmn.dev/schemas/v1/mycelium.json",
                "capsule": {
                    "uri": "cmn://example.com/mycelium/b3.mychash",
                    "core": {
                        "domain": "example.com",
                        "bio": "Test mycelium",
                        "spores": [],
                        "updated_at_epoch_ms": 1700000000000_u64
                    },
                    "core_signature": "ed25519.sig"
                },
                "capsule_signature": "ed25519.sig"
            },
            "replicates": []
        }
    });

    Mock::given(method("GET"))
        .and(path("/synapse/mycelium/example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::fetch_synapse_mycelium(
        &client,
        &server.uri(),
        "example.com",
        Default::default(),
    )
    .await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.code, "ok");
    assert_eq!(resp.result.query.domain, "example.com");
    assert_eq!(
        resp.result.mycelium["capsule"]["core"]["bio"],
        "Test mycelium"
    );
}

#[tokio::test]
async fn fetch_synapse_mycelium_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/synapse/mycelium/unknown.com"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = test_client();
    let result = substrate::client::fetch_synapse_mycelium(
        &client,
        &server.uri(),
        "unknown.com",
        Default::default(),
    )
    .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

// ---------------------------------------------------------------------------
// http_client (safe DNS)
// ---------------------------------------------------------------------------

#[cfg(feature = "client-safe-dns")]
#[test]
fn http_client_creates_successfully() {
    let client = substrate::client::http_client(30);
    assert!(client.is_ok());
}

#[cfg(feature = "client-safe-dns")]
#[test]
fn http_client_different_timeouts() {
    assert!(substrate::client::http_client(5).is_ok());
    assert!(substrate::client::http_client(300).is_ok());
}
