package org.springaicommunity.mcp.security.tests.streamable.sync.httpclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.spec.McpSchema;
import java.io.IOException;
import java.net.http.HttpClient;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.tests.McpClientConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

/**
 * Note: Here specify the main configuration class so that nested tests know which
 * configuration to pick up. Otherwise, configuration scanning does not find the nested
 * config class in {@link Nested} tests.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = """
				spring.ai.mcp.client.streamable-http.connections.greeter.url=${mcp.server.url}
				mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServerToolsSecured
				""")
@ActiveProfiles("sync")
class StreamableHttpToolsSecuredTests {

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@Value("${mcp.server.url}")
	String mcpServerUrl;

	@LocalServerPort
	int port;

	WebClient webClient = new WebClient();

	McpSyncClient mcpClient;

	@BeforeEach
	void setUp() {
		webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		var transport = HttpClientStreamableHttpTransport.builder(mcpServerUrl)
			.jsonMapper(new JacksonMcpJsonMapper(new ObjectMapper()))
			.clientBuilder(HttpClient.newBuilder())
			.build();
		this.mcpClient = McpClient.sync(transport)
			.clientInfo(new McpSchema.Implementation("test-client", new McpClientCommonProperties().getVersion()))
			.requestTimeout(new McpClientCommonProperties().getRequestTimeout())
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();
	}

	@AfterEach
	void tearDown() {
		this.mcpClient.closeGracefully();
	}

	/**
	 * You do not need tokens to list tools.
	 */
	@Test
	void mcpServerUnsecured() {
		var resp = mcpClient.listTools();

		assertThat(resp.tools()).hasSize(1).first().extracting(McpSchema.Tool::name).isEqualTo("greeter");
	}

	/**
	 * You need a valid access token to call a tool.
	 */
	@Test
	void callToolSecured() {
		var resp = mcpClient.callTool(McpSchema.CallToolRequest.builder().name("greeter").build());

		assertThat(resp.isError()).isTrue();
		assertThat(resp.content()).first()
			.asInstanceOf(type(McpSchema.TextContent.class))
			.extracting(McpSchema.TextContent::text)
			.isEqualTo("not authenticated");
	}

	@Test
	void callToolWithToken() throws IOException {
		ensureAuthServerLogin();

		var response = webClient.getPage("http://127.0.0.1:" + port + "/tool/call?clientName=greeter&toolName=greeter");
		var contentAsString = response.getWebResponse().getContentAsString();
		assertThat(contentAsString)
			.isEqualTo("Called [client: greeter, tool: greeter], got response [Hello test-user]");
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

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class, SseHttpClientTransportAutoConfiguration.class,
			SseWebFluxTransportAutoConfiguration.class, StreamableHttpWebFluxTransportAutoConfiguration.class })
	@Import({ McpClientConfiguration.class, AuthorizationServerConfiguration.class, McpServerConfiguration.class })
	static class StreamableHttpToolsSecuredConfig {

		@Bean
		McpSyncHttpClientRequestCustomizer requestCustomizer(OAuth2AuthorizedClientManager clientManager) {
			return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(clientManager, "authserver");
		}

	}

}
