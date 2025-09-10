package org.springaicommunity.mcp.security.tests.streamable.sync;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.spec.McpSchema;
import java.io.IOException;
import java.net.http.HttpClient;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.resourceserver.authentication.BearerResourceMetadataTokenAuthenticationEntryPoint;
import org.springaicommunity.mcp.security.resourceserver.config.McpResourceServerConfigurer;
import org.springaicommunity.mcp.security.resourceserver.metadata.ResourceIdentifier;
import org.springaicommunity.mcp.security.tests.AllowAllCorsConfigurationSource;
import org.springaicommunity.mcp.security.tests.McpClientConfiguration;
import org.springaicommunity.mcp.security.tests.common.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.streamable.sync.servers.StreamableHttpMcpServerToolsSecured;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.experimental.boot.server.exec.CommonsExecWebServerFactoryBean;
import org.springframework.experimental.boot.server.exec.MavenClasspathEntry;
import org.springframework.experimental.boot.test.context.DynamicPortUrl;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.InstanceOfAssertFactories.type;
import static org.springframework.experimental.boot.server.exec.MavenClasspathEntry.springBootStarter;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = "spring.ai.mcp.client.streamable-http.connections.greeter.url=${mcp.server.url}")
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
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		var transport = HttpClientStreamableHttpTransport.builder(mcpServerUrl)
			.objectMapper(new ObjectMapper())
			.clientBuilder(HttpClient.newBuilder())
			.build();
		this.mcpClient = McpClient.sync(transport)
			.clientInfo(new McpSchema.Implementation("test-client", new McpClientCommonProperties().getVersion()))
			.requestTimeout(new McpClientCommonProperties().getRequestTimeout())
			.transportContextProvider(new AuthenticationMcpTransportContextProvider())
			.build();
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
			OAuth2AuthorizationServerJwtAutoConfiguration.class })
	@Import(McpClientConfiguration.class)
	static class StreamableHttpConfig {

		@Bean
		@DynamicPortUrl(name = "mcp.server.url")
		public CommonsExecWebServerFactoryBean mcpServer(@Value("${authorization.server.url}") String issuerUri) {
			// The properties file is inferred from the bean name, here it's in
			// resources/testjars/mcpServer
			return CommonsExecWebServerFactoryBean.builder()
				.useGenericSpringBootMain()
				.setAdditionalBeanClassNames(StreamableHttpMcpServerToolsSecured.class.getName())
				.systemProperties(props -> {
					props.putIfAbsent("spring.security.oauth2.resourceserver.jwt.issuer-uri", issuerUri);
					props.putIfAbsent("spring.ai.mcp.server.protocol", "STREAMABLE");
				})
				.classpath((classpath) -> classpath
					.entries(springBootStarter("web"), springBootStarter("oauth2-resource-server"),
							springAiStarter("mcp-server-webmvc"))
					.classes(StreamableHttpMcpServerToolsSecured.class)
					.classes(McpResourceServerConfigurer.class)
					.classes(BearerResourceMetadataTokenAuthenticationEntryPoint.class)
					.classes(AllowAllCorsConfigurationSource.class)
					.scan(ResourceIdentifier.class));
		}

		@Bean
		@DynamicPortUrl(name = "authorization.server.url")
		static CommonsExecWebServerFactoryBean authorizationServer() {
			// The properties file is inferred from the bean name, here it's in
			// resources/testjars/authorizationServer
			return CommonsExecWebServerFactoryBean.builder()
				.useGenericSpringBootMain()
				.setAdditionalBeanClassNames(AuthorizationServerConfiguration.class.getName())
				.classpath((classpath) -> classpath.entries(springBootStarter("oauth2-authorization-server"))
					.classes(AuthorizationServerConfiguration.class)
					.classes(AllowAllCorsConfigurationSource.class));
		}

		@Bean
		McpSyncHttpClientRequestCustomizer requestCustomizer(OAuth2AuthorizedClientManager clientManager) {
			return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(clientManager, "authserver");
		}

	}

	public static MavenClasspathEntry springAiStarter(String starterName) {
		return new MavenClasspathEntry("org.springframework.ai:spring-ai-starter-" + starterName + ":1.1.0-M1");
	}

}
