package org.springaicommunity.mcp.security.tests.chat.streaming;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Function;

import com.anthropic.client.AnthropicClient;
import com.anthropic.client.AnthropicClientAsync;
import com.anthropic.core.JsonNull;
import com.anthropic.core.JsonString;
import com.anthropic.core.http.AsyncStreamResponse;
import com.anthropic.models.messages.Container;
import com.anthropic.models.messages.ContentBlock;
import com.anthropic.models.messages.ContentBlockParam;
import com.anthropic.models.messages.DirectCaller;
import com.anthropic.models.messages.InputJsonDelta;
import com.anthropic.models.messages.Message;
import com.anthropic.models.messages.MessageCreateParams;
import com.anthropic.models.messages.MessageDeltaUsage;
import com.anthropic.models.messages.MessageParam;
import com.anthropic.models.messages.Model;
import com.anthropic.models.messages.RawContentBlockDelta;
import com.anthropic.models.messages.RawContentBlockDeltaEvent;
import com.anthropic.models.messages.RawContentBlockStartEvent;
import com.anthropic.models.messages.RawContentBlockStopEvent;
import com.anthropic.models.messages.RawMessageDeltaEvent;
import com.anthropic.models.messages.RawMessageStartEvent;
import com.anthropic.models.messages.RawMessageStreamEvent;
import com.anthropic.models.messages.StopReason;
import com.anthropic.models.messages.TextBlock;
import com.anthropic.models.messages.TextDelta;
import com.anthropic.models.messages.ToolResultBlockParam;
import com.anthropic.models.messages.ToolUseBlock;
import com.anthropic.models.messages.Usage;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
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
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import org.springframework.ai.anthropic.AnthropicChatModel;
import org.springframework.ai.anthropic.AnthropicChatOptions;
import org.springframework.ai.mcp.client.httpclient.autoconfigure.SseHttpClientTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.SseWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.client.webflux.autoconfigure.StreamableHttpWebFluxTransportAutoConfiguration;
import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatProperties;
import org.springframework.ai.model.tool.DefaultToolExecutionEligibilityPredicate;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

/**
 * These tests mock interacting with the LLM, and letting the
 * {@link org.springframework.ai.chat.model.ChatModel} drive the interactions with the MCP
 * server.
 * <p>
 * This is useful for {@code chatClient.prompt("...").stream()} interactions, which
 * require writing to the chat client's reactor context.
 * <p>
 * It relies on horrible {@link AnthropicClient} mocks, and even horribler
 * {@link AnthropicClientAsync} mocks.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = """
		spring.ai.mcp.client.streamable-http.connections.greeter.url=${mcp.server.url}
		spring.ai.mcp.client.initialized=false
		mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer
		mcp.server.protocol=STATELESS
		""")
@ActiveProfiles("sync")
class LlmTests {

	// LLM mock: base request that we don't care much about
	private final Message baseMessage = Message.builder()
		.content(Collections.emptyList())
		.id("m1234")
		.model(Model.CLAUDE_HAIKU_4_5)
		.stopReason(StopReason.TOOL_USE)
		.stopSequence("")
		.usage(mock(Usage.class))
		.build();

	// LLM mock: First response, ask to call the "greeter" tool
	private final Message firstResponse = baseMessage.toBuilder()
		.content(List.of(ContentBlock.ofToolUse(ToolUseBlock.builder()
			.name("greeter")
			.id("toolu_1234")
			.id("b1234")
			.type(JsonString.of("tool_use"))
			.caller(ToolUseBlock.Caller.ofDirect(DirectCaller.builder().build()))
			.input(JsonNull.of())
			.build())))
		.build();

	// LLM mock: greeter tool has been called, the LLM now responds with
	// "Got tool response [...]", wrapping the greeter tool response.
	private final Function<String, Message> makeFinalResponse = (String toolResponse) -> baseMessage.toBuilder()
		.content(List.of(ContentBlock.ofText(TextBlock.builder()
			.text("Got tool response [%s]".formatted(toolResponse))
			.citations(Optional.empty())
			.build())))
		.build();

	@Value("${authorization.server.url}")
	String authorizationServerUrl;

	@LocalServerPort
	int port;

	WebClient webClient = new WebClient();

	@Autowired
	private AnthropicClient anthropicClient;

	@Autowired
	private AnthropicClientAsync anthropicClientAsync;

	@BeforeEach
	void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);

		reset(anthropicClient);
		reset(anthropicClientAsync);

		// --- Sync client mocking (for chatClient.prompt().call()) ---
		when(anthropicClient.messages().create(argThat(LlmTests::hasSingleAnthropicMessage))).thenReturn(firstResponse);
		when(anthropicClient.messages().create(argThat(LlmTests::hasToolCallResult))).thenAnswer(invocation -> {
			MessageCreateParams messageParams = invocation.getArgument(0);
			var toolResponse = extractToolResponse(messageParams);
			return makeFinalResponse.apply(toolResponse);
		});

		// --- Async client mocking (for chatClient.prompt().stream()) ---
		when(anthropicClientAsync.messages().createStreaming(argThat(LlmTests::hasSingleAnthropicMessage)))
			.thenReturn(fakeAsyncStreamResponse(messageToStreamEvents(firstResponse)));
		when(anthropicClientAsync.messages().createStreaming(argThat(LlmTests::hasToolCallResult)))
			.thenAnswer(invocation -> {
				MessageCreateParams messageParams = invocation.getArgument(0);
				var toolResponse = extractToolResponse(messageParams);
				return fakeAsyncStreamResponse(messageToStreamEvents(makeFinalResponse.apply(toolResponse)));
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
		assertThat(contentAsString).contains("error when sending message");
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
		McpClientCustomizer<McpClient.SyncSpec> syncClientCustomizer() {
			return (name, syncSpec) -> syncSpec
				.transportContextProvider(new AuthenticationMcpTransportContextProvider());
		}

		@Bean
		McpClientCustomizer<HttpClientStreamableHttpTransport.Builder> transportCustomizer(
				OAuth2AuthorizedClientManager clientManager,
				ClientRegistrationRepository clientRegistrationRepository) {
			return (name, builder) -> builder
				.httpRequestCustomizer(new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(clientManager,
						clientRegistrationRepository, "authserver"));
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
				.oauth2Client(Customizer.withDefaults())
				.build();
		}

		@Bean
		AnthropicClient anthropicClient() {
			return mock(AnthropicClient.class, RETURNS_DEEP_STUBS);
		}

		@Bean
		AnthropicClientAsync anthropicClientAsync() {
			return mock(AnthropicClientAsync.class, RETURNS_DEEP_STUBS);
		}

		@Bean
		public AnthropicChatModel anthropicChatModel(AnthropicChatProperties chatProperties,
				ToolCallingManager toolCallingManager, AnthropicClient anthropicClient,
				AnthropicClientAsync anthropicClientAsync) {
			AnthropicChatOptions options = chatProperties.getOptions();

			return AnthropicChatModel.builder()
				.options(options)
				.toolCallingManager(toolCallingManager)
				.toolExecutionEligibilityPredicate(new DefaultToolExecutionEligibilityPredicate())
				.anthropicClient(anthropicClient)
				.anthropicClientAsync(anthropicClientAsync)
				.build();
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

	// Anthropic mocking and Mockito argument matching
	// Hic sunt dracones.
	private static boolean hasToolCallResult(MessageCreateParams messageCreateParams) {
		return messageCreateParams != null && messageCreateParams.messages()
			.stream()
			.map(MessageParam::content)
			.filter(MessageParam.Content::isBlockParams)
			.map(MessageParam.Content::asBlockParams)
			.flatMap(Collection::stream)
			.anyMatch(ContentBlockParam::isToolResult);
	}

	private static boolean hasSingleAnthropicMessage(MessageCreateParams messageCreateParams) {
		return messageCreateParams != null && messageCreateParams.messages().size() == 1;
	}

	private String extractToolResponse(MessageCreateParams messageCreateParams) {
		return messageCreateParams.messages()
			.stream()
			.map(MessageParam::content)
			.filter(MessageParam.Content::isBlockParams)
			.map(MessageParam.Content::asBlockParams)
			.flatMap(Collection::stream)
			.filter(ContentBlockParam::isToolResult)
			.map(ContentBlockParam::asToolResult)
			.map(ToolResultBlockParam::content)
			.flatMap(Optional::stream)
			.map(ToolResultBlockParam.Content::string)
			.flatMap(Optional::stream)
			.map(this::deserializeToolResult)
			.findFirst()
			.get();
	}

	record ToolResult(@JsonProperty("text") String text) {

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

	private static List<RawMessageStreamEvent> messageToStreamEvents(Message message) {
		List<RawMessageStreamEvent> events = new ArrayList<>();

		events.add(RawMessageStreamEvent.ofMessageStart(RawMessageStartEvent.builder().message(message).build()));

		for (int i = 0; i < message.content().size(); i++) {
			ContentBlock block = message.content().get(i);

			RawContentBlockStartEvent.ContentBlock startBlock;
			RawContentBlockDeltaEvent deltaEvent;

			if (block.isToolUse()) {
				ToolUseBlock toolUse = block.asToolUse();
				startBlock = RawContentBlockStartEvent.ContentBlock.ofToolUse(ToolUseBlock.builder()
					.id(toolUse.id())
					.name(toolUse.name())
					.type(JsonString.of("tool_use"))
					.caller(toolUse.caller())
					.input(JsonNull.of())
					.build());
				deltaEvent = RawContentBlockDeltaEvent.builder()
					.index(i)
					.delta(RawContentBlockDelta.ofInputJson(InputJsonDelta.builder().partialJson("{}").build()))
					.build();
			}
			else if (block.isText()) {
				TextBlock textBlock = block.asText();
				startBlock = RawContentBlockStartEvent.ContentBlock
					.ofText(TextBlock.builder().text("").citations(Optional.empty()).build());
				deltaEvent = RawContentBlockDeltaEvent.builder()
					.index(i)
					.delta(RawContentBlockDelta.ofText(TextDelta.builder().text(textBlock.text()).build()))
					.build();
			}
			else {
				continue;
			}

			events.add(RawMessageStreamEvent
				.ofContentBlockStart(RawContentBlockStartEvent.builder().contentBlock(startBlock).index(i).build()));
			events.add(RawMessageStreamEvent.ofContentBlockDelta(deltaEvent));
			events.add(RawMessageStreamEvent.ofContentBlockStop(RawContentBlockStopEvent.builder().index(i).build()));
		}

		StopReason stopReason = message.stopReason().orElse(StopReason.END_TURN);
		String stopSequence = message.stopSequence().orElse(null);
		events.add(RawMessageStreamEvent.ofMessageDelta(RawMessageDeltaEvent.builder()
			.delta(RawMessageDeltaEvent.Delta.builder()
				.stopReason(stopReason)
				.stopSequence(stopSequence)
				.container((Container) null)
				.build())
			.usage(mock(MessageDeltaUsage.class))
			.build()));

		return events;
	}

	private static <T> AsyncStreamResponse<T> fakeAsyncStreamResponse(List<T> events) {
		return new AsyncStreamResponse<T>() {
			private final CompletableFuture<Void> completeFuture = new CompletableFuture<>();

			@Override
			public AsyncStreamResponse<T> subscribe(Handler<? super T> handler) {
				try {
					for (T event : events) {
						handler.onNext(event);
					}
					handler.onComplete(Optional.empty());
					completeFuture.complete(null);
				}
				catch (Exception e) {
					handler.onComplete(Optional.of(e));
					completeFuture.completeExceptionally(e);
				}
				return this;
			}

			@Override
			public AsyncStreamResponse<T> subscribe(Handler<? super T> handler, Executor executor) {
				return subscribe(handler);
			}

			@Override
			public CompletableFuture<Void> onCompleteFuture() {
				return completeFuture;
			}

			@Override
			public void close() {
			}
		};
	}

}
