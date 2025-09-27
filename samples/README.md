# MCP Security: Samples

These are samples for testing MCP Security integration. It contains two samples:

- An Authorization Server, to issue tokens
- An MCP Server, protected by OAuth 2.0

## Usage

1. Run the authorization server, with `./mvnw spring-boot:run`. The authorization server will start
   on http://localhost:9000. To log in when using the authorization code flow, use `user` / `password`. To request
   tokens using the client credentials grant, use `default-client` and `default-secret`.

1. Run the MCP server called `sample-mcp-server`, with `./mvnw spring-boot:run`. The server will start on http://localhost:8090, and the SSE
   endpoint is http://localhost:8090/sse. It is a protected OAuth2 authorization server, and requires an access token to
   obtain responses. Optionally, to test the connection manually, [obtain an access token](#obtaining-an-access-token)
   and then run:

   ```shell
   curl "http://localhost:8090/sse" \
     --header "Authorization: Bearer <YOUR ACCESS TOKEN>"
   ```

1. To explore the MCP Server using the [MCP inspector](https://modelcontextprotocol.io/legacy/tools/inspector), launch
   the inspector:

   ```shell
   npx @modelcontextprotocol/inspector@latest
   ```

1. Set the following values in the menu on the left, and then click "connect":
    - Transport: SSE
    - URL: `http://localhost:8090/sse`
    - Authentication > OAuth 2.0 Flow > Client ID: `default-client`.
    - Leave the Redirect URL as-is.

1. This should open a pane on the right side of the MCP inspector. Navigate to the "tools" tab, then list the tools.

## Appendix

### Obtaining an access token

If you would like to obtain an access token for debugging, without the MCP inspector, call the Authorization Server
directly, using the client credentials grant:

   ```shell
   curl -XPOST "http://localhost:9000/oauth2/token" \
     --data "grant_type=client_credentials" \
     --user "default-client:default-secret"
   ```
