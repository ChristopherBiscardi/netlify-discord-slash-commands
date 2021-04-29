.PHONY: deploy build

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## build the cargo binary
	cargo build --target x86_64-unknown-linux-musl --release

deploy: build ## deploy the site to netlify
	cp target/x86_64-unknown-linux-musl/release/_in-progress-netlify-discord-slash-commands functions/interactions
	netlify deploy --prod

create-guild-command:  ## Create a guild-scoped command. Guild commands update instantly and should be used for testing
	@curl -XPOST \
	  -H "Content-Type: application/json" \
	  -H "Authorization: Bot $DISCORD_BOT_TOKEN" \
	  -d @./interactions/role.json \
	  https://discord.com/api/v8/applications/810835719329021973/guilds/810835070964203520/commands 

