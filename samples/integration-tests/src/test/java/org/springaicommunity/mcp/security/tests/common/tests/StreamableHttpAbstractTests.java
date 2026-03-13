package org.springaicommunity.mcp.security.tests.common.tests;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.McpHttpClientTransportAuthorizationException;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationRequest;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;
import org.springaicommunity.mcp.security.tests.InMemoryMcpClientRepository;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.EnabledIf;
import org.springframework.test.json.JsonContent;
import org.springframework.test.json.JsonContentAssert;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

@ActiveProfiles("sync")
public abstract class StreamableHttpAbstractTests {

	public abstract McpClientTransport buildNoSecurityTransport();

	public abstract McpClientTransport buildAuthorizationCodeTransport();

	public abstract McpClientTransport buildHybridTransport();

	public abstract McpClientTransport buildClientCredentialsTransport();

	public abstract McpClientTransport buildTokenTransport(AtomicReference<String> currentToken);

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@LocalServerPort
	int port;

	@Value("${mcp.server.url}")
	protected String mcpServerUrl;

	WebClient webClient = new WebClient();

	@Autowired
	protected ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	protected OAuth2AuthorizedClientService authorizedClientService;

	@Autowired
	protected OAuth2AuthorizedClientManager clientManager;

	@Autowired
	private InMemoryMcpClientRepository inMemoryMcpClientRepository;

	@Autowired
	private McpOAuth2ClientManager mcpClientManager;

	protected AuthorizedClientServiceOAuth2AuthorizedClientManager clientCredentialsClientManager;

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		this.clientCredentialsClientManager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientService);
	}

	@Test
	@DisplayName("Can fetch resource metadata")
	void resourceMetadata() {
		var restClient = RestClient.builder().defaultStatusHandler(status -> true, (request, response) -> {
		}).build();
		var response = restClient.post().uri(mcpServerUrl + "/mcp").retrieve().toBodilessEntity();

		assertThat(response.getStatusCode().value()).isEqualTo(401);
		var wwwAuthenticate = response.getHeaders().get("www-authenticate").get(0);
		var pattern = Pattern.compile("^Bearer resource_metadata=(?<metadataUrl>.*)$");
		assertThat(wwwAuthenticate).matches(pattern);

		var matcher = pattern.matcher(wwwAuthenticate);
		assertThat(matcher.find()).isTrue();
		var metadataUrl = matcher.group("metadataUrl");
		assertThat(metadataUrl).contains(".well-known/oauth-protected-resource");

		var protectedResourceMetadata = restClient.get().uri(metadataUrl).retrieve().body(String.class);
		new JsonContentAssert(new JsonContent(protectedResourceMetadata))
			.hasPathSatisfying("$.resource", r -> assertThat(r).isEqualTo(mcpServerUrl + "/mcp"))
			.hasPathSatisfying("$.authorization_servers[0]", as -> assertThat(as).isEqualTo(authorizationServerUrl));
	}

	@Test
	@DisplayName("Without oauth2 support, cannot initialize")
	void whenNoOAuthCapabilitiesCannotInitialize() {
		var transport = buildNoSecurityTransport();

		var mcpClientBuilder = McpClient.sync(transport)
			.clientInfo(new McpSchema.Implementation("test-client", new McpClientCommonProperties().getVersion()))
			.requestTimeout(new McpClientCommonProperties().getRequestTimeout());

		try (var mcpClient = mcpClientBuilder.build()) {
			assertThatThrownBy(mcpClient::initialize).hasMessage("Client failed to initialize by explicit API call")
				.rootCause()
				// Note: this should be better handled by the Java-SDK.
				// Today, the HTTP 401 response is wrapped in a RuntimeException with
				// a poor String representation.
				.isInstanceOf(RuntimeException.class)
				.satisfiesAnyOf(e -> {
					// message with http client
					assertThat(e).hasMessageStartingWith("Authorization error when sending message");
				}, e -> {
					// message with webclient
					assertThat(e).hasMessageStartingWith("401 Unauthorized from POST");
				});
		}
		catch (Exception e) {
			fail(e);
		}
	}

	@Test
	@DisplayName("With authorization_code, when no user is present, cannot initialize")
	void noUser() throws IOException {
		ensureAuthServerLogin();

		var transport = buildAuthorizationCodeTransport();

		var mcpClientBuilder = McpClient.sync(transport)
			.transportContextProvider(new AuthenticationMcpTransportContextProvider());

		try (var mcpClient = mcpClientBuilder.build()) {
			assertThatThrownBy(mcpClient::initialize).hasMessage("Client failed to initialize by explicit API call")
				.rootCause()
				// Note: this should be better handled by the Java-SDK.
				// Today, the HTTP 401 response is wrapped in a RuntimeException with
				// a poor String representation.
				.isInstanceOf(RuntimeException.class)
				.satisfiesAnyOf(e -> {
					// message with http client
					assertThat(e).isInstanceOf(McpHttpClientTransportAuthorizationException.class)
						.hasMessage("Authorization error when sending message")
						.extracting("responseInfo", type(HttpResponse.ResponseInfo.class))
						.extracting(HttpResponse.ResponseInfo::statusCode)
						.isEqualTo(401);
				}, e -> {
					// message with webclient
					assertThat(e).hasMessageStartingWith("401 Unauthorized from POST");
				});
		}
	}

	@Test
	@DisplayName("When no user is present, can use client_credentials and get a token")
	void whenClientCredentialsCanCall() {
		var transport = buildClientCredentialsTransport();
		var mcpClientBuilder = McpClient.sync(transport)
			// No authentication context provider required, as this does not rely on
			// thread locals
			.clientInfo(new McpSchema.Implementation("test-client", new McpClientCommonProperties().getVersion()))
			.requestTimeout(new McpClientCommonProperties().getRequestTimeout());

		try (var mcpClient = mcpClientBuilder.build()) {
			var resp = mcpClient.callTool(McpSchema.CallToolRequest.builder().name("greeter").build());

			assertThat(resp.content()).hasSize(1)
				.first()
				.asInstanceOf(type(McpSchema.TextContent.class))
				.extracting(McpSchema.TextContent::text)
				// the "sub" of the token used in the request is the client id, in
				// client_credentials
				.isEqualTo("Hello default-client");
		}
		catch (Exception e) {
			fail(e);
		}
	}

	@Test
	@DisplayName("With hybrid, can use both client_credentials and authorization_code flows")
	void whenHybridAndClientCredentialsCanCall() throws IOException {
		// We need to create two clients because session binding is active,
		// each transport session will be bound to a specific user (oauth2 client or
		// end-user)
		var authorizationCodeClient = McpClient.sync(buildHybridTransport())
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();
		var clientCredentialsClient = McpClient.sync(buildHybridTransport())
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();

		inMemoryMcpClientRepository.addClient("test-client-hybrid", authorizationCodeClient);

		var resp = clientCredentialsClient.callTool(McpSchema.CallToolRequest.builder().name("greeter").build());

		assertThat(resp.content()).hasSize(1)
			.first()
			.asInstanceOf(type(McpSchema.TextContent.class))
			.extracting(McpSchema.TextContent::text)
			// the "sub" of the token used in the request is the client id, in
			// client_credentials
			.isEqualTo("Hello default-client");

		ensureAuthServerLogin();
		var callToolResponse = webClient
			.getPage("http://127.0.0.1:" + port + "/tool/call?clientName=test-client-hybrid&toolName=greeter");
		var contentAsString = callToolResponse.getWebResponse().getContentAsString();
		// The "sub" of the token is "test-user" in authorization_code flow
		assertThat(contentAsString)
			.isEqualTo("Called [client: test-client-hybrid, tool: greeter], got response [Hello test-user]");

	}

	@Test
	@DisplayName("With authorization_code, when the user is present, can call tool")
	void addToolThenCall() throws IOException {
		ensureAuthServerLogin();

		var transport = buildAuthorizationCodeTransport();

		var client = McpClient.sync(transport)
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();
		inMemoryMcpClientRepository.addClient("test-client-authcode", client);

		var callToolResponse = webClient
			.getPage("http://127.0.0.1:" + port + "/tool/call?clientName=test-client-authcode&toolName=greeter");
		var contentAsString = callToolResponse.getWebResponse().getContentAsString();
		assertThat(contentAsString)
			.isEqualTo("Called [client: test-client-authcode, tool: greeter], got response [Hello test-user]");
	}

	@Test
	@DisplayName("Enforces sessions binding")
	// Stateless transport does not have session IDs
	@EnabledIf(value = "#{'${mcp.server.protocol}'.equals('STREAMABLE')}", loadContext = true)
	void sessionBinding() {
		var firstRegistrationId = "first";
		mcpClientManager.registerMcpClient(firstRegistrationId, mcpServerUrl + "/mcp",
				DynamicClientRegistrationRequest.builder()
					.grantTypes(List.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
					.build());
		var secondRegistrationId = "second";
		mcpClientManager.registerMcpClient(secondRegistrationId, mcpServerUrl + "/mcp",
				DynamicClientRegistrationRequest.builder()
					.grantTypes(List.of(AuthorizationGrantType.CLIENT_CREDENTIALS))
					.build());

		var firstToken = this.clientCredentialsClientManager
			.authorize(OAuth2AuthorizeRequest.withClientRegistrationId(firstRegistrationId)
				.principal("mcp-client-service")
				.build())
			.getAccessToken()
			.getTokenValue();
		var secondToken = this.clientCredentialsClientManager
			.authorize(OAuth2AuthorizeRequest.withClientRegistrationId(secondRegistrationId)
				.principal("mcp-client-service")
				.build())
			.getAccessToken()
			.getTokenValue();
		var currentToken = new AtomicReference<String>();
		var transport = buildTokenTransport(currentToken);

		var client = McpClient.sync(transport)
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();

		currentToken.set(firstToken);
		var firstResponse = client.callTool(McpSchema.CallToolRequest.builder().name("greeter").build());
		assertThat(firstResponse.isError()).isFalse();

		currentToken.set(secondToken);
		assertThatThrownBy(() -> client.callTool(McpSchema.CallToolRequest.builder().name("greeter").build()))
			.satisfiesAnyOf(e -> {
				// HttpClient
				assertThat(e).isInstanceOf(McpHttpClientTransportAuthorizationException.class)
					.extracting("responseInfo", type(HttpResponse.ResponseInfo.class))
					.extracting(HttpResponse.ResponseInfo::statusCode)
					.isEqualTo(403);
			}, e -> {
				// WebClient
				assertThat(e).rootCause().hasMessageContaining("403 Forbidden from POST");
			});
	}

	private void ensureAuthServerLogin() throws IOException {
		HtmlPage loginPage = this.webClient.getPage(authorizationServerUrl);

		if (loginPage.getWebResponse().getStatusCode() == 404) {
			// Already logged in
			return;
		}
		loginPage.<HtmlInput>querySelector("#username").type("test-user");
		loginPage.<HtmlInput>querySelector("#password").type("test-password");
		loginPage.<HtmlButton>querySelector("button").click();
	}

}
