use ed25519_dalek::PublicKey;
use lamedh_http::{
    lambda::{lambda, Context},
    IntoResponse, Request,
};
use lazy_static::lazy_static;
use std::env;

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

#[lambda(http)]
#[tokio::main]
async fn main(
    _: Request,
    _: Context,
) -> Result<impl IntoResponse, Error> {
    dbg!("in main");
    Ok("boop")
}
