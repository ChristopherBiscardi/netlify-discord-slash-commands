use anyhow::{anyhow, Context as C};
use aws_lambda_events::encodings::Body;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use http::{
    header::CONTENT_TYPE, HeaderMap, Response, StatusCode,
};
use lamedh_http::{
    lambda::{run, Context},
    IntoResponse, Request,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{collections::HashMap, env};
use tracing::{error, info, instrument};

type Error =
    Box<dyn std::error::Error + Send + Sync + 'static>;

const DISCORD_API: &str = "https://discord.com/api/v9";
const USER_AGENT: &str = concat!(
	"DiscordBot (https://github.com/partycorgi/discord-slash-commands, ",
	env!("CARGO_PKG_VERSION"),
	")"
);

lazy_static! {
    static ref PUB_KEY: PublicKey = PublicKey::from_bytes(
        &hex::decode(
            env::var("DISCORD_PUBLIC_KEY")
              .expect("Expected DISCORD_PUBLIC_KEY to be set in the environment")
        )
        .expect("Couldn't hex::decode the DISCORD_PUBLIC_KEY")
    )
    .expect("Couldn't create a PublicKey from DISCORD_PUBLIC_KEY bytes");
    static ref DISCORD_BOT_TOKEN: String = env::var("DISCORD_BOT_TOKEN")
        .expect("Expected a DISCORD_BOT_TOKEN");
static ref ROLE_REVERSE_MAP: HashMap<&'static str, &'static str> = {
    let mut map = HashMap::new();
    map.insert("837304749312180285", "corgi");
    map
};
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
    if let Err(_) = validate_discord_signature(
        event.headers(),
        event.body(),
        &PUB_KEY,
    ) {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::Text(
                "invalid request signature".to_string(),
            ))
            .expect("response builder failed"));
    };

    let interaction: Interaction =
        serde_json::from_slice(event.body())?;
    match interaction.interaction_type {
        InteractionType::Ping => Ok(InteractionResponse {
            interaction_response_type:
                InteractionResponseType::Pong,
            data: None,
        }
        .into_response()),
        InteractionType::ApplicationCommand => {
            match interaction.data {
                Some(
                    ApplicationCommandInteractionData {
                        id,
                        name,
                        options,
                    },
                ) => {
                    info!(
                        %id,
                        %name, "handling ApplicationCommand"
                    );
                    match name.as_str() {
                        "role" => {
                            let maybe_user = &interaction
                                .member
                                .map(|member| member.user);
                            let maybe_guild_id =
                                interaction.guild_id;
                            let maybe_role = options
                                .and_then(|options| {
                                    options
                                        .iter()
                                        .find(|option| {
                                            option.name == "i-want-to-be-a"
                                        }).and_then(|v|{
                                            v.value.clone()
                                        })
                                });
                            match (
                                maybe_user,
                                maybe_guild_id,
                                maybe_role,
                            ) {
                                (
                                    Some(user),
                                    Some(guild_id),
                                    Some(role),
                                ) => {
                                    let response = set_role_for_user_in_guild(
                                    role, &user, guild_id,
                                )
                                .await;
                                    Ok(response
                                        .into_response())
                                }
                                (
                                    maybe_user,
                                    maybe_guild_id,
                                    maybe_role,
                                ) => {
                                    error!(?maybe_user,
                                    ?maybe_guild_id,
                                    ?maybe_role,
                                    "necessary information was not available");
                                    Ok(InteractionResponse::reply(
                                    "received role command"
                                        .to_string(),
                                )
                                .into_response())
                                }
                            }
                        }
                        _ => {
                            error!(
                                %id,
                                %name,
                                ?options,
                                "unknown command"
                            );
                            Ok(InteractionResponse::reply(format!("received unknown command: {}", name)).into_response())
                        }
                    }
                }

                _ => {
                    error!(
                        ?interaction,
                        "something is wrong"
                    );
                    Ok(InteractionResponse::reply("Something went wrong when processing interaction".to_string()).into_response())
                }
            }
        }
    }
}

async fn set_role_for_user_in_guild<T: AsRef<str>>(
    role: T,
    user: &User,
    guild_id: Snowflake,
) -> InteractionResponse {
    let client = reqwest::Client::new();
    let res = client
        .put(&format!(
            "{}/guilds/{}/members/{}/roles/{}",
            DISCORD_API,
            guild_id,
            user.id,
            role.as_ref()
        ))
        .header("User-Agent", USER_AGENT)
        .header(
            "Authorization",
            format!("Bot {}", DISCORD_BOT_TOKEN.clone()),
        )
        .send()
        .await;

    match res {
        Err(e) => {
            error!(error = ?e);
            InteractionResponse::reply(format!(
                "failed to set role for {}",
                user.username
            ))
        }
        Ok(response) => {
            if response.status().is_success() {
                match ROLE_REVERSE_MAP.get(role.as_ref()) {
                    Some(name) => {
                        InteractionResponse::reply(format!(
                            "{} has accepted the {} role",
                            user.username, name
                        ))
                    }
                    None => {
                        InteractionResponse::reply(format!(
                            "{} has accepted a role",
                            user.username
                        ))
                    }
                }
            } else {
                InteractionResponse::reply(format!(
                    "Failed with status code {}",
                    response.status()
                ))
            }
        }
    }
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
    interaction_type: InteractionType,
    data: Option<ApplicationCommandInteractionData>,
    guild_id: Option<Snowflake>,
    channel_id: Option<Snowflake>,
    member: Option<GuildMember>,
    token: String,
    version: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuildMember {
    pub deaf: bool,
    pub nick: Option<String>,
    pub roles: Vec<String>,
    /// Attached User struct.
    pub user: User,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct User {
    pub id: Snowflake,
    pub avatar: Option<String>,
    pub bot: Option<bool>,
    pub discriminator: String,
    pub username: String,
}
#[derive(Deserialize_repr, Debug)]
#[repr(u8)]
pub enum InteractionType {
    Ping = 1,
    ApplicationCommand = 2,
}

type Snowflake = String;
#[derive(Debug, Deserialize)]
struct ApplicationCommandInteractionData {
    id: Snowflake,
    name: String,
    //resolved: Option<ApplicationCommandInteractionDataResolved>
    options: Option<
        Vec<ApplicationCommandInteractionDataOption>,
    >,
}

#[derive(Debug, Deserialize)]
struct ApplicationCommandInteractionDataOption {
    name: String,
    #[serde(rename = "type")]
    option_type: ApplicationCommandOptionType,
    // the value of the pair
    value: Option<String>,
    // present if this option is a group or subcommand
    options: Option<
        Vec<ApplicationCommandInteractionDataOption>,
    >,
}
#[derive(Deserialize_repr, Debug)]
#[repr(u8)]
enum ApplicationCommandOptionType {
    SUBCOMMAND = 1,
    SUBCOMMANDGROUP = 2,
    STRING = 3,
    INTEGER = 4,
    BOOLEAN = 5,
    USER = 6,
    CHANNEL = 7,
    ROLE = 8,
}

#[derive(Serialize, Debug)]
struct InteractionResponse {
    #[serde(rename = "type")]
    interaction_response_type: InteractionResponseType,
    data: Option<InteractionApplicationCommandCallbackData>,
}

impl InteractionResponse {
    fn reply(content: String) -> InteractionResponse {
        InteractionResponse{
            interaction_response_type: InteractionResponseType::ChannelMessageWithSource,
            data: Some(InteractionApplicationCommandCallbackData {
                tts: None,
                content: Some(content),
                flags: None
            })
        }
    }
}

impl IntoResponse for InteractionResponse {
    fn into_response(self) -> Response<Body> {
        Response::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_string(&self)
                    .expect("unable to serialize serde_json::Value")
                    .into(),
            )
            .expect("unable to build http::Response")
    }
}

#[derive(Serialize_repr, Debug)]
#[repr(u8)]
pub enum InteractionResponseType {
    Pong = 1,
    // Acknowledge = 2,
    // ChannelMessage = 3,
    ChannelMessageWithSource = 4,
    ACKWithSource = 5,
}

#[derive(Serialize, Debug)]
struct InteractionApplicationCommandCallbackData {
    tts: Option<bool>,
    content: Option<String>,
    // embeds
    // allowed_mentions
    flags: Option<usize>,
}
