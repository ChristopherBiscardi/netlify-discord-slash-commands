use anyhow::{anyhow, Context as C};
use aws_lambda_events::encodings::Body;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use http::HeaderMap;
use lamedh_http::{
    lambda::{run, Context},
    IntoResponse, Request,
};
use lazy_static::lazy_static;
use serde::Deserialize;
use serde_repr::Deserialize_repr;
use std::env;
use tracing::{info, instrument};

type Error =
    Box<dyn std::error::Error + Send + Sync + 'static>;

lazy_static! {
    static ref PUB_KEY: PublicKey = PublicKey::from_bytes(
        &hex::decode(
            env::var("DISCORD_PUBLIC_KEY")
              .expect("Expected DISCORD_PUBLIC_KEY to be set in the environment")
        )
        .expect("Couldn't hex::decode the DISCORD_PUBLIC_KEY")
    )
    .expect("Couldn't create a PublicKey from DISCORD_PUBLIC_KEY bytes");
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let my_subscriber = tracing_subscriber::fmt().finish();
    tracing::subscriber::set_global_default(my_subscriber)
        .expect("setting tracing default failed");

    run(lamedh_http::handler(handler)).await?;
    Ok(())
}
#[instrument]
async fn handler(
    event: Request,
    _: Context,
) -> Result<impl IntoResponse, Error> {
    info!("in handler");
    validate_discord_signature(
        event.headers(),
        event.body(),
        &PUB_KEY,
    )?;
    let interaction: Interaction =
        serde_json::from_slice(event.body())?;
    dbg!(interaction);
    Ok("boop")
}

/// Verify the discord signature using your application's publickey,
/// the `X-Signature-Ed25519` and `X-Signature-Timestamp` headers,
/// and the request body.
///
/// This is required because discord will send you a ping when
/// you set up your webhook URL, as well as random invalid input
/// periodically that has to be rejected.
#[instrument(skip(headers, body, pub_key), err)]
pub fn validate_discord_signature(
    headers: &HeaderMap,
    body: &Body,
    pub_key: &PublicKey,
) -> anyhow::Result<()> {
    let sig_ed25519 = {
        let header_signature = headers
            .get("X-Signature-Ed25519")
            .ok_or(anyhow!(
                "missing X-Signature-Ed25519 header"
            ))?;
        let decoded_header = hex::decode(header_signature)
            .context(
                "Failed to decode ed25519 signature header",
            )?;

        let mut sig_arr: [u8; 64] = [0; 64];
        for (i, byte) in
            decoded_header.into_iter().enumerate()
        {
            sig_arr[i] = byte;
        }
        Signature::new(sig_arr)
    };
    let sig_timestamp =
        headers.get("X-Signature-Timestamp").ok_or(
            anyhow!("missing X-Signature-Timestamp header"),
        )?;

    if let Body::Text(body) = body {
        let content = sig_timestamp
            .as_bytes()
            .iter()
            .chain(body.as_bytes().iter())
            .cloned()
            .collect::<Vec<u8>>();

        pub_key
            .verify(&content, &sig_ed25519)
            .context("Failed to verify the http body against the signature with the given public key")
    } else {
        Err(anyhow!("Invalid body type"))
    }
}

#[derive(Debug, Deserialize)]
struct Interaction {
    #[serde(rename = "type")]
    event_type: InteractionType,
}

#[derive(Deserialize_repr, Debug)]
#[repr(u8)]
pub enum InteractionType {
    Ping = 1,
    ApplicationCommand = 2,
}
