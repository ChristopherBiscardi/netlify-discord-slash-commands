# Netlify Discord Slash Command Handling

This repo consists of two crates

- A library for building discord slash command handlers
- A function that uses the crate as an example

---

### Steps

1. Create a new discord server
1. [Create an Application](https://discord.com/developers/applications)
1. Using ngrok to debug serverless function requests

   - set interactions endpoint
   - Check log at /inspect/http
   - ends at
   - > interactions_endpoint_url: The specified interactions endpoint url could not be verified.

1. set up new netlify site and deploy first rust function
   - See same payload as before
1. Build out signature verification
   - https://discord.com/developers/docs/interactions/slash-commands#security-and-authorization
1. k

1. Register a bot with commands privs so we can access the http api
1. Register a new command (guild vs global command)
1. Set up a Netlify Function powered by Rust
1. [Optional] cross compile from macos
1. Create a role in discord to self-assign (order matters)
1. Publish library to crates.io
