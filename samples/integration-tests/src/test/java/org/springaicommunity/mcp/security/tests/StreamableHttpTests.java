package org.springaicommunity.mcp.security.tests;

import io.modelcontextprotocol.client.McpSyncClient;
import java.io.IOException;
import java.util.List;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.resourceserver.authentication.BearerResourceMetadataTokenAuthenticationEntryPoint;
import org.springaicommunity.mcp.security.resourceserver.config.McpResourceServerConfigurer;
import org.springaicommunity.mcp.security.resourceserver.metadata.ResourceIdentifier;
import org.springaicommunity.mcp.security.sample.authorizationserver.SampleAuthorizationServerApplication;
import org.springaicommunity.mcp.security.tests.servers.StreamableHttpMcpServer;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.experimental.boot.server.exec.MavenClasspathEntry.springBootStarter;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class StreamableHttpTests {

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@LocalServerPort
	int port;

	@Autowired
	List<McpSyncClient> mcpClients;

	WebClient webClient = new WebClient();

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
	}

	@Test
	void callTool() throws IOException {
		ensureAuthServerLogin();

		var response = webClient.getPage("http://127.0.0.1:" + port + "/tool/call?clientName=greeter&toolName=greeter");
		var contentAsString = response.getWebResponse().getContentAsString();
		assertThat(contentAsString).isEqualTo("Called [client: greeter, tool: greeter], got response [Hello world!]");
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
		public CommonsExecWebServerFactoryBean mcpServer(@Value("${authorization.server.url}") String issuerUri)
				throws Exception {
			return CommonsExecWebServerFactoryBean.builder()
				.useGenericSpringBootMain()
				.setAdditionalBeanClassNames(StreamableHttpMcpServer.class.getName())
				.systemProperties(
						props -> props.putIfAbsent("spring.security.oauth2.resourceserver.jwt.issuer-uri", issuerUri))
				.classpath((classpath) -> classpath
					.entries(springBootStarter("web"), springBootStarter("oauth2-resource-server"),
							springAiStarter("mcp-server-webmvc"))
					.scan(StreamableHttpMcpServer.class)
					.scan(McpResourceServerConfigurer.class)
					.scan(ResourceIdentifier.class)
					.scan(BearerResourceMetadataTokenAuthenticationEntryPoint.class)
				// TODO: reference config explicitly
				);
		}

		@Bean
		@DynamicPortUrl(name = "authorization.server.url")
		static CommonsExecWebServerFactoryBean authorizationServer() {
			return CommonsExecWebServerFactoryBean.builder()
				.mainClass(SampleAuthorizationServerApplication.class.getName())
				.classpath((classpath) -> classpath
					// Add spring-boot-starter-authorization-server & transitive
					// dependencies
					.entries(springBootStarter("oauth2-authorization-server"))
					.scan(SampleAuthorizationServerApplication.class)
				// TODO: reference config explicitly
				);
		}

	}

	public static MavenClasspathEntry springAiStarter(String starterName) {
		return new MavenClasspathEntry("org.springframework.ai:spring-ai-starter-" + starterName + ":1.1.0-SNAPSHOT");
	}

}
