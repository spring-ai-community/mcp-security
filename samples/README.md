# MCP Security: Samples

These are samples for testing MCP Security integration. It contains many "flavors" of samples, including some MCP
clients using different Spring technologies.

Here we will demonstrate how to use an OAuth 2.1-secured MCP server. This requires running both the MCP server and an
OAuth 2.1 Authorization Server that will issue access tokens for the Server.

## Usage

1. Run the authorization server, with `./mvnw spring-boot:run`. The authorization server will start
   on http://localhost:9000. To log in when using the authorization code flow, use `user` / `password`. To request
   tokens using the client credentials grant, use `default-client` and `default-secret`.

1. Run the MCP server called `sample-mcp-server`, with `./mvnw spring-boot:run`. The server will start
   on http://localhost:8090, and the MCP endpoint is http://localhost:8090/mcp. It is a protected OAuth2 authorization
   server, and requires an access token to obtain responses. We recommend using the MCP inspector to test the server,
   see below. Optionally, to test the connection manually, [obtain an access token](#obtaining-an-access-token) and then
   run:

"capabilities":{"roots":{}},

   ```shell
   curl -XPOST "http://localhost:8090/mcp" \
      -d '{"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"curl-client","version":"0.19.0"}},"jsonrpc":"2.0","id":0}' \
      --header "Accept: application/json" \
      --header "Accept: text/event-stream" \
      --header "Content-type: application/json" \
      --header "Authorization: Bearer <YOUR-TOKEN>"
   ```

1. To explore the MCP Server using the [MCP inspector](https://modelcontextprotocol.io/legacy/tools/inspector), launch
   the inspector:

   ```shell
   npx @modelcontextprotocol/inspector@latest
   ```

1. Set the following values in the menu on the left, and then click "connect":
    - Transport: Streamable HTTP
    - URL: `http://localhost:8090/mcp`
    - Use "Connection type: Direct"
    - Click connect

1. This should redirect you to the auth server for login (with `user` and `password`). Submit consent on the following
   screen.

1. After log in, a pane should on the right side of the MCP inspector. Navigate to the "tools" tab, then list the tools.

## Appendix

### Obtaining an access token

If you would like to obtain an access token for debugging, without the MCP inspector, call the Authorization Server
directly, using the client credentials grant:

   ```shell
   curl -XPOST "http://localhost:9000/oauth2/token" \
     --data "grant_type=client_credentials" \
     --user "default-client:default-secret"
   ```
