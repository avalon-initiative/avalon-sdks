//! Discovery, reachability, selection wiring and cross-check of the client-built known list,
//! against stubbed nodes.

use std::sync::Arc;

use avalon_sdk::known_list::{
    build_known_list, cross_check_head, discover_candidates, BuildKnownListOptions, KnownWitness,
};
use avalon_sdk::sth::sign_tree_head;
use avalon_sdk::witness::{
    sign_witness_cosignature, witness_announce_message, CosignedTreeHead, WitnessCosignature,
};
use ed25519_dalek::{Signer, SigningKey};
use time::OffsetDateTime;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NET: &str = "net";

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_id(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().as_bytes())
}

fn peer(k: &SigningKey, base_url: &str, network: &str, at: OffsetDateTime) -> serde_json::Value {
    let id = key_id(k);
    let proof = hex::encode(
        k.sign(&witness_announce_message(base_url, &id, at))
            .to_bytes(),
    );
    serde_json::json!({"base_url": base_url, "network_id": network,
        "witness": {"key_id": id, "announced_at": rfc3339(at), "proof": proof}})
}

async fn seed_with(peers: Vec<serde_json::Value>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nodes/discover"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"self_status": {}, "peers": peers})),
        )
        .mount(&server)
        .await;
    server
}

async fn live_node(network: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ledger/sth/latest"))
        .and(query_param("shard_id", "core"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"network_id": network, "tree_size": 1})),
        )
        .mount(&server)
        .await;
    server
}

fn ids(list: &[KnownWitness]) -> Vec<String> {
    list.iter().map(|w| w.key_id.clone()).collect()
}

#[tokio::test]
async fn discovery_unions_seeds_filters_and_detects_anchors() {
    let now = OffsetDateTime::now_utc();
    let (a, b, c, d, e) = (key(1), key(2), key(3), key(4), key(5));
    let mut forged = peer(&e, "http://e.example.com", NET, now);
    forged["witness"]["proof"] = serde_json::json!("00".repeat(64));
    let seed_two = seed_with(vec![
        peer(&b, "http://b.example.com", NET, now),
        peer(&b, "http://b-other.example.com", NET, now),
        peer(&c, "http://c.example.com", "other-net", now),
        forged,
        peer(
            &d,
            "http://d.example.com",
            NET,
            now - time::Duration::hours(2),
        ),
    ])
    .await;
    let seed_one = seed_with(vec![
        peer(&a, "http://a.example.com", NET, now),
        peer(&b, "http://b.example.com", NET, now),
        peer(&a, &seed_two.uri(), NET, now),
        serde_json::json!({"base_url": "http://plain.example.com", "network_id": NET}),
    ])
    .await;
    let dead = "http://127.0.0.1:1".to_string();
    let seeds = vec![dead, seed_one.uri(), seed_two.uri()];
    let found = discover_candidates(&reqwest::Client::new(), NET, &seeds, now).await;
    let got: Vec<_> = found
        .iter()
        .map(|c| (c.witness_key_id.clone(), c.base_url.clone(), c.is_anchor))
        .collect();
    assert_eq!(
        got,
        vec![
            (key_id(&a), "http://a.example.com".to_string(), false),
            (key_id(&b), "http://b.example.com".to_string(), false),
        ]
    );
}

#[tokio::test]
async fn a_candidate_at_a_seed_url_is_an_anchor_and_sorts_first() {
    let now = OffsetDateTime::now_utc();
    let (a, b) = (key(1), key(2));
    let node = live_node(NET).await;
    let upper = node.uri().replace("http://", "HTTP://") + "/";
    let seed = seed_with(vec![
        peer(&a, "http://a.example.com", NET, now),
        peer(&b, &node.uri(), NET, now),
    ])
    .await;
    let seeds = vec![seed.uri(), upper];
    let found = discover_candidates(&reqwest::Client::new(), NET, &seeds, now).await;
    assert_eq!(found[0].witness_key_id, key_id(&b));
    assert!(found[0].is_anchor);
    assert!(!found[1].is_anchor);
}

#[tokio::test]
async fn no_reachable_seed_gives_an_empty_list() {
    let mut options = BuildKnownListOptions::new(NET, vec!["http://127.0.0.1:1".to_string()]);
    options.now = Some(OffsetDateTime::now_utc());
    assert!(build_known_list(&reqwest::Client::new(), &options)
        .await
        .is_empty());
}

#[tokio::test]
async fn unreachable_and_wrong_network_candidates_are_dropped() {
    let now = OffsetDateTime::now_utc();
    let good = live_node(NET).await;
    let wrong = live_node("other").await;
    let down = MockServer::start().await;
    let (a, b, c) = (key(1), key(2), key(3));
    let seed = seed_with(vec![
        peer(&a, &down.uri(), NET, now),
        peer(&b, &wrong.uri(), NET, now),
        peer(&c, &good.uri(), NET, now),
    ])
    .await;
    let mut options = BuildKnownListOptions::new(NET, vec![seed.uri()]);
    options.max_per_prefix = 10;
    let list = build_known_list(&reqwest::Client::new(), &options).await;
    assert_eq!(ids(&list), vec![key_id(&c)]);
    assert_eq!(list[0].base_url.as_deref(), Some(good.uri().as_str()));
}

#[tokio::test]
async fn probing_is_bounded_and_follows_the_injected_order() {
    let now = OffsetDateTime::now_utc();
    let mut peers = Vec::new();
    let mut servers = Vec::new();
    for i in 0..8u8 {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ledger/sth/latest"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&s)
            .await;
        peers.push(peer(&key(i + 1), &s.uri(), NET, now));
        servers.push(s);
    }
    let seed = seed_with(peers).await;
    let mut options = BuildKnownListOptions::new(NET, vec![seed.uri()]);
    options.capacity = 2;
    options.max_per_prefix = 10;
    options.shuffle = Some(Arc::new(|c| c.reverse()));
    assert!(build_known_list(&reqwest::Client::new(), &options)
        .await
        .is_empty());
    let mut probed = Vec::new();
    for (i, s) in servers.iter().enumerate() {
        probed.push((i, s.received_requests().await.unwrap().len()));
    }
    assert_eq!(probed.iter().map(|p| p.1).sum::<usize>(), 6);
    assert!(probed[2..].iter().all(|p| p.1 == 1) && probed[..2].iter().all(|p| p.1 == 0));
}

#[tokio::test]
async fn probing_stops_once_capacity_is_filled() {
    let now = OffsetDateTime::now_utc();
    let mut peers = Vec::new();
    let mut servers = Vec::new();
    for i in 0..10u8 {
        let s = live_node(NET).await;
        peers.push(peer(&key(i + 1), &s.uri(), NET, now));
        servers.push(s);
    }
    let seed = seed_with(peers).await;
    let mut options = BuildKnownListOptions::new(NET, vec![seed.uri()]);
    options.capacity = 2;
    options.max_per_prefix = 10;
    options.shuffle = Some(Arc::new(|_| {}));
    let list = build_known_list(&reqwest::Client::new(), &options).await;
    assert_eq!(list.len(), 2);
    let mut total = 0;
    for s in &servers {
        total += s.received_requests().await.unwrap().len();
    }
    assert_eq!(total, 4);
}

fn head_json(head: &CosignedTreeHead) -> serde_json::Value {
    serde_json::json!({
        "tree_size": head.sth.tree_size, "root_hash": head.sth.root_hash,
        "network_id": head.sth.network_id, "signing_key_id": head.sth.signing_key_id,
        "signature": head.sth.signature, "created_at": rfc3339(head.sth.created_at),
        "cosignatures": head.cosignatures.iter().map(|c: &WitnessCosignature| serde_json::json!({
            "witness_key_id": c.witness_key_id, "observed_at": rfc3339(c.observed_at),
            "signature": c.signature})).collect::<Vec<_>>(),
    })
}

fn cosigned(
    author: &SigningKey,
    root: &str,
    signers: &[&SigningKey],
    now: OffsetDateTime,
) -> CosignedTreeHead {
    let sth = sign_tree_head(author, "k", 7, root, NET, now);
    let cosignatures = signers
        .iter()
        .map(|k| sign_witness_cosignature(k, &sth, now))
        .collect();
    CosignedTreeHead { sth, cosignatures }
}

#[tokio::test]
async fn cross_check_reports_a_conflicting_author_signed_head() {
    let now = OffsetDateTime::now_utc();
    let author = key(1);
    let (w1, w2, w3, w4, w5) = (key(2), key(3), key(4), key(5), key(6));
    let accepted = cosigned(&author, &"aa".repeat(32), &[&w1, &w2, &w4], now);
    let conflicting = cosigned(&author, &"bb".repeat(32), &[&w2, &w3, &w5], now);
    let forged = cosigned(&key(9), &"cc".repeat(32), &[&w1], now);
    let same = accepted.clone();
    let mut known = Vec::new();
    let mut servers = Vec::new();
    for (w, body) in [
        (&w1, Some(&same)),
        (&w2, Some(&conflicting)),
        (&w3, Some(&forged)),
        (&w4, None),
    ] {
        let s = MockServer::start().await;
        let mock = Mock::given(method("GET"))
            .and(path("/ledger/sth/7"))
            .and(query_param("witnesses", "1"))
            .and(query_param("shard_id", "core"));
        match body {
            Some(h) => mock.respond_with(ResponseTemplate::new(200).set_body_json(head_json(h))),
            None => mock.respond_with(ResponseTemplate::new(500)),
        }
        .mount(&s)
        .await;
        let mut kw = KnownWitness::from_key(w.verifying_key());
        kw.base_url = Some(s.uri());
        known.push(kw);
        servers.push(s);
    }
    known.push(KnownWitness::from_key(w5.verifying_key()));
    let evidence = cross_check_head(
        &reqwest::Client::new(),
        &known,
        &accepted,
        &author.verifying_key(),
        now - time::Duration::minutes(10),
        now + time::Duration::seconds(1),
    )
    .await;
    assert_eq!(evidence.len(), 1);
    let e = &evidence[0];
    assert_eq!(
        (e.tree_size, e.root_a.as_str()),
        (7, "aa".repeat(32).as_str())
    );
    assert_eq!(e.root_b, "bb".repeat(32));
    assert_eq!(e.sources, vec![known[1].base_url.clone().unwrap()]);
    assert_eq!(e.witnesses, vec![key_id(&w2)]);
}

#[tokio::test]
async fn cross_check_is_empty_when_nothing_conflicts_or_nothing_answers() {
    let now = OffsetDateTime::now_utc();
    let author = key(1);
    let accepted = cosigned(&author, &"aa".repeat(32), &[], now);
    let mut kw = KnownWitness::from_key(key(2).verifying_key());
    kw.base_url = Some("http://127.0.0.1:1".to_string());
    let evidence = cross_check_head(
        &reqwest::Client::new(),
        &[kw],
        &accepted,
        &author.verifying_key(),
        now - time::Duration::minutes(10),
        now,
    )
    .await;
    assert!(evidence.is_empty());
}
