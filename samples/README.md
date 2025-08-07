# MCP Security: Samples

These are samples for testing MCP Security integration. It contains two samples:

- An Authorization Server, to issue tokens
- An MCP Server, protected by OAuth 2.0

## Usage

1. Run the authorization server, with `./mvnw spring-boot:run`. The authorization server will start
   on http://localhost:9000. To log in when using the authorization code flow, use `user1` / `password`. To request
   tokens using the client credentials grant, use `default-client` and `default-secret`.
1. Obtain an access_token using the client credentials grant. For example, use:

   ```shell
   curl -XPOST "http://localhost:9000/oauth2/token" \
     --data "grant_type=client_credentials" \
     --user "default-client:default-secret"
   ```

1. Run the MCP server, with `./mvnw spring-boot:run`. The server will start on http://localhost:8090, and the SSE
   endpoint is http://localhost:8090/sse. It is a protected OAuth2 authorization server, and requires an access token to
   obtain responses. You can verify your connection by using the token from the previous step, and opening an SSE
   stream, for example with cURL:

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
    - URL: http://localhost:8090/sse
    - Authentication > API Authentication Token > Bearer Token: The token you obtained from the previous steps.
