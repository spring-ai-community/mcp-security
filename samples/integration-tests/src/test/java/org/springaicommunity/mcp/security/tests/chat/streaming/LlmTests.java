package org.springaicommunity.mcp.security.tests.chat.streaming;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import org.htmlunit.WebClient;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.tests.InMemoryMcpClientRepository;
import org.springaicommunity.mcp.security.tests.McpController;
import org.springaicommunity.mcp.security.tests.common.configuration.AuthorizationServerConfiguration;
import org.springaicommunity.mcp.security.tests.common.configuration.McpServerConfiguration;
import reactor.core.publisher.Flux;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import org.springframework.ai.anthropic.api.AnthropicApi;
import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.customizer.McpSyncClientCustomizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

/**
 * These tests mock interacting with the LLM, and letting the
 * {@link org.springframework.ai.chat.model.ChatModel} drive the interactions with the MCP
 * server.
 * <p>
 * This is useful for {@code chatClient.prompt("...").stream()} interactions, which
 * require writing to the chat client's reactor context.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		spring.ai.mcp.client.streamable-http.connections.greeter.url=${mcp.server.url}
		spring.ai.mcp.client.initialized=false
		mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer
		mcp.server.protocol=STATELESS
		""")
@ActiveProfiles("sync")
class LlmTests {

	// Ask to call the "greeter" tool
	private final AnthropicApi.ChatCompletionResponse firstResponse = new AnthropicApi.ChatCompletionResponse(
			"msg_1234", "message", AnthropicApi.Role.ASSISTANT,
			List.of(new AnthropicApi.ContentBlock(AnthropicApi.ContentBlock.Type.TOOL_USE, "toolu_1234", "greeter",
					Map.of())),
			"AnthropicApi.ChatModel.CLAUDE_3_7_SONNET", "tool_use", null, null, null);

	private final Function<String, AnthropicApi.ChatCompletionResponse> makeFinalResponse = (
			String message) -> new AnthropicApi.ChatCompletionResponse("msg_1234", "message",
					AnthropicApi.Role.ASSISTANT,
					List.of(new AnthropicApi.ContentBlock(message,
							(AnthropicApi.ChatCompletionRequest.CacheControl) null)), // contents
					"AnthropicApi.ChatModel.CLAUDE_3_7_SONNET", "end_turn", null, null, null);

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@LocalServerPort
	int port;

	WebClient webClient = new WebClient();

	@MockitoBean
	private AnthropicApi api;

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);

		reset(api);

		// Initial call
		when(api.chatCompletionEntity(argThat(LlmTests::hasSingleAnthropicMessage), any()))
			.thenReturn(ResponseEntity.ok(firstResponse));

		// Call with embedded tool results
		when(api.chatCompletionEntity(argThat(LlmTests::hasToolCallResult), any())).thenAnswer(invocation -> {
			var completionRequest = ((AnthropicApi.ChatCompletionRequest) invocation.getArgument(0));
			var toolResponse = extractToolResponse(completionRequest);
			return ResponseEntity.ok(makeFinalResponse.apply("Got tool response [%s]".formatted(toolResponse)));
		});

		// Initial call
		when(api.chatCompletionStream(argThat(LlmTests::hasSingleAnthropicMessage), any()))
			.thenReturn(Flux.just(firstResponse));

		// Call with embedded tool results
		when(api.chatCompletionStream(argThat(LlmTests::hasToolCallResult), any())).thenAnswer(invocation -> {
			var completionRequest = ((AnthropicApi.ChatCompletionRequest) invocation.getArgument(0));
			var toolResponse = extractToolResponse(completionRequest);
			return Flux.just(makeFinalResponse.apply("Got tool response [%s]".formatted(toolResponse)));
		});
	}

	@Test
	void chatClientChat() throws IOException {
		ensureAuthServerLogin();

		var resp = webClient.getPage("http://127.0.0.1:" + port + "/chat?question=doesnt-matter");
		var contentAsString = resp.getWebResponse().getContentAsString();
		assertThat(contentAsString).isEqualTo("Got tool response [Hello test-user]");
	}

	@Test
	void chatClientStream() throws IOException {
		ensureAuthServerLogin();

		var resp = webClient.getPage("http://127.0.0.1:" + port + "/stream?question=doesnt-matter");
		var contentAsString = resp.getWebResponse().getContentAsString();
		assertThat(contentAsString).isEqualTo("Got tool response [Hello test-user]");
	}

	@Test
	void chatClientStreamNoContext() throws IOException {
		ensureAuthServerLogin();

		var resp = webClient.getPage("http://127.0.0.1:" + port + "/stream-no-context?question=doesnt-matter");
		var contentAsString = resp.getWebResponse().getContentAsString();
		assertThat(contentAsString).contains("Failed to send message");
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@EnableAutoConfiguration(exclude = { OAuth2AuthorizationServerAutoConfiguration.class,
			OAuth2AuthorizationServerJwtAutoConfiguration.class, SseHttpClientTransportAutoConfiguration.class,
			SseWebFluxTransportAutoConfiguration.class, StreamableHttpWebFluxTransportAutoConfiguration.class })
	@Import({ AuthorizationServerConfiguration.class, McpServerConfiguration.class, InMemoryMcpClientRepository.class,
			McpController.class })
	static class StreamableHttpConfig {

		@Bean
		McpSyncClientCustomizer syncClientCustomizer() {
			return (name, syncSpec) -> syncSpec
				.transportContextProvider(new AuthenticationMcpTransportContextProvider());
		}

		@Bean
		McpSyncHttpClientRequestCustomizer requestCustomizer(OAuth2AuthorizedClientManager clientManager) {
			return new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(clientManager, "authserver");
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				.oauth2Client(Customizer.withDefaults())
				.build();
		}

	}

	record ToolResult(@JsonProperty("text") String text) {

	}

	private static boolean hasToolCallResult(AnthropicApi.ChatCompletionRequest argument) {
		return argument != null && argument.messages()
			.stream()
			.map(AnthropicApi.AnthropicMessage::content)
			.flatMap(Collection::stream)
			.map(AnthropicApi.ContentBlock::type)
			.anyMatch(AnthropicApi.ContentBlock.Type.TOOL_RESULT::equals);
	}

	private static boolean hasSingleAnthropicMessage(AnthropicApi.ChatCompletionRequest argument) {
		return argument != null && argument.messages().size() == 1;
	}

	private String extractToolResponse(AnthropicApi.ChatCompletionRequest completionRequest) {
		return completionRequest.messages()
			.stream()
			.map(AnthropicApi.AnthropicMessage::content)
			.map(c -> c.get(0))
			.filter(m -> m.type().equals(AnthropicApi.ContentBlock.Type.TOOL_RESULT))
			.map(AnthropicApi.ContentBlock::content)
			.map(content -> deserializeToolResult(content.toString()))
			.findFirst()
			.get();
	}

	private String deserializeToolResult(String content) {
		try {
			List<ToolResult> results = new ObjectMapper().readValue(content, new TypeReference<>() {
			});
			return results.get(0).text();
		}
		catch (JacksonException e) {
			return content;
		}
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
