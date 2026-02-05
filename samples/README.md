# MCP Security: Samples

This directory contains sample applications demonstrating the various features of the MCP Security
library. Each sample showcases a different aspect of securing MCP servers and clients.

## Sample Applications

Core samples are:

| Sample                        | Description                                                                           | Port |
|-------------------------------|---------------------------------------------------------------------------------------|------|
| `sample-authorization-server` | OAuth 2.1 Authorization Server for issuing access tokens, compatible with MCP clients | 9000 |
| `sample-mcp-server`           | OAuth 2.0-secured MCP server                                                          | 8090 |
| `sample-mcp-client`           | MCP client using HttpClient transport with OAuth 2.0                                  | 8080 |
| `sample-mcp-server-api-key`   | MCP server secured with API keys                                                      | 8092 |

Additional samples include:

| Sample                            | Description                                                    | Port |
|-----------------------------------|----------------------------------------------------------------|------|
| `sample-mcp-server-secured-tools` | MCP server with method-level security on individual tools      | 8091 |
| `sample-mcp-client-webclient`     | MCP client using WebClient (reactive) transport with OAuth 2.0 | 8081 |
| `integration-tests`               | Automated integration tests for all modules                    | N/A  |

---

## 1. OAuth 2.0-Secured MCP Server

This scenario demonstrates an MCP server protected by OAuth 2.0. The server exposes two tools:

- **`current-temperature`**: Fetches real-time weather data from the Open-Meteo API. This demonstrates
  a typical external API integration.
- **`greet`**: Returns a personalized greeting using the authenticated user's name from the security
  context. This demonstrates how tools can access the current user's identity.

### Prerequisites

Start the authorization server first. It issues the access tokens required by the MCP server.

```shell
./mvnw spring-boot:run -pl samples/sample-authorization-server
```

The authorization server starts on http://localhost:9000. Credentials:

- User login: `user` / `password`
- Client credentials: `default-client` / `default-secret`

### Running the MCP Server

```shell
./mvnw spring-boot:run -pl samples/sample-mcp-server
```

The server starts on http://localhost:8090, with the MCP endpoint at http://localhost:8090/mcp.

### Testing with the MCP Inspector

The [MCP Inspector](https://modelcontextprotocol.io/legacy/tools/inspector) provides an interactive
way to explore and test the server.

1. Launch the inspector:

   ```shell
   npx @modelcontextprotocol/inspector@latest
   ```

2. Configure the connection:
    - Transport: Streamable HTTP
    - URL: `http://localhost:8090/mcp`
    - Connection type: Direct

3. Click "Connect". You will be redirected to the authorization server to log in with `user` / `password`.
   Submit consent on the following screen.

4. After authentication, navigate to the "Tools" tab and click "List Tools" to see the available tools.
   Try calling the `greet` tool to see it return a greeting with your username.

### Testing with curl

To test manually without the inspector, first obtain an access token using the client credentials grant:

```shell
curl -XPOST "http://localhost:9000/oauth2/token" \
  --data "grant_type=client_credentials" \
  --user "default-client:default-secret"
```

Extract the `access_token` from the response and use it to call the MCP endpoint:

```shell
export OAUTH2_TOKEN=<your token goes here>

curl -XPOST "http://localhost:8090/mcp" \
   -d '{"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"curl-client","version":"0.19.0"}},"jsonrpc":"2.0","id":0}' \
   --header "Accept: application/json" \
   --header "Accept: text/event-stream" \
   --header "Content-type: application/json" \
   --header "Authorization: Bearer $OAUTH2_TOKEN"
```

---

## 2. End-to-End Scenario with Authorization Server, MCP Server, and MCP Client

This scenario demonstrates a complete integration where an MCP client connects to an OAuth 2.0-protected
MCP server. The client obtains tokens from the authorization server and uses them to call MCP tools,
which are then used by an LLM to answer user questions.

### AI model

This sample uses Anthropic as the AI model provider. Set your Anthropic API key as an environment variable:

```shell
export ANTHROPIC_API_KEY=<your-api-key>
```

Note: To use a different model provider, update the dependencies in the client's `pom.xml` and configure the appropriate
properties.

### Running the Full Stack

Start all three applications in separate terminals, in the following order:

1. Authorization Server:
   ```shell
   ./mvnw spring-boot:run -pl samples/sample-authorization-server
   ```

2. MCP Server:
   ```shell
   ./mvnw spring-boot:run -pl samples/sample-mcp-server
   ```

3. MCP Client (HttpClient-based):
   ```shell
   ./mvnw spring-boot:run -pl samples/sample-mcp-client
   ```

### Using the Application

1. Open http://localhost:8080 in your browser.
2. Enter a city name (e.g., "Paris") and click "Ask the LLM".
3. You will be redirected to the authorization server for login. Use `user` / `password`.
4. After authentication, the LLM will use the MCP server's weather tool to fetch and display the
   current temperature.

### Alternative: WebClient-Based Client

You can also run the WebClient-based MCP client, which uses Spring's reactive `WebClient` instead of
the JDK's `HttpClient` for the MCP transport layer:

```shell
./mvnw spring-boot:run -pl samples/sample-mcp-client-webclient
```

This client runs on port 8081. The functionality is identical, demonstrating that both transport
implementations work with OAuth 2.0 security.

---

## 3. API Key Authentication

This scenario demonstrates securing an MCP server with API keys instead of OAuth 2.0. This approach
is simpler and suitable for scenarios where OAuth 2.0 is not required.

### Running the API Key Server

You do not need to run the authorization server for this sample.

```shell
./mvnw spring-boot:run -pl samples/sample-mcp-server-api-key
```

The server starts on http://localhost:8092.

### Testing with curl

The sample is preconfigured with an API key, `api01.mycustomapikey`. Use it in the `X-API-Key` header:

```shell
curl -XPOST "http://localhost:8092/mcp" \
   -d '{"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"curl-client","version":"0.19.0"}},"jsonrpc":"2.0","id":0}' \
   --header "Accept: application/json" \
   --header "Accept: text/event-stream" \
   --header "Content-type: application/json" \
   --header "X-API-Key: api01.mycustomapikey"
```

### Testing with the MCP Inspector

1. Launch the inspector:

   ```shell
   npx @modelcontextprotocol/inspector@latest
   ```

2. Configure the connection:
    - Transport: Streamable HTTP
    - URL: `http://localhost:8092/mcp`
    - Connection type: Direct
    - Add a custom header: `X-API-Key` with value `api01.mycustomapikey`

3. Click "Connect" to access the server.

---


## 4. Secured Tools with Method-Level Security

This scenario demonstrates securing individual tools rather than the entire MCP server. The server
allows unauthenticated access to `initialize` and `tools/list`, but requires authentication when
calling specific tools.

### How It Works

The server configuration uses `@EnableMethodSecurity` and permits all requests at the HTTP level:

```java
.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
```

Individual tools are then protected using `@PreAuthorize` annotations:

```java
@PreAuthorize("isAuthenticated()")
@McpTool(name = "temperature-history", ...)
public ToolResponse getHistoricalWeatherData(...) { ...}
```

This means:

- Clients can discover available tools without authentication
- Calling a protected tool without a valid token results in an error

### Running the Secured Tools Server

Start both the authorization server and the secured tools server:

```shell
./mvnw spring-boot:run -pl samples/sample-authorization-server
./mvnw spring-boot:run -pl samples/sample-mcp-server-secured-tools
```

The server runs on http://localhost:8091.

### Limitations with the MCP Inspector

The MCP Inspector cannot fully test this scenario. When connecting without authentication, the
inspector can list tools but fails when attempting to call a protected tool. However, the inspector's
OAuth 2.0 flow only activates when the server returns authentication requirements during the
`initialize` call. Since `initialize` is public in this configuration, the inspector does not prompt
for login, and there is no way to manually provide a token for tool calls.

To test this scenario, use an MCP client application (like `sample-mcp-client`) that handles the
OAuth 2.0 flow at the tool-call level, or use curl with a manually obtained token.
