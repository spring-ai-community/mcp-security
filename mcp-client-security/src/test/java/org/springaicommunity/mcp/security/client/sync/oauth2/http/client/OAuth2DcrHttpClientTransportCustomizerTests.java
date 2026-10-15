/*
 * Copyright 2026-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client;

import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.Map;

import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpAsyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.client.transport.customizer.McpHttpClientTransportAuthorizationErrorHandler;
import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2DcrClientManager;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Daniel Garnier-Moiroux
 */
class OAuth2DcrHttpClientTransportCustomizerTests {

	private final OAuth2AuthorizedClientManager authorizedClientManager = mock(OAuth2AuthorizedClientManager.class);

	private final ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);

	private final McpOAuth2DcrClientManager mcpOAuth2ClientManager = mock(McpOAuth2DcrClientManager.class);

	@Test
	void constructorRejectsEmptyDefaultRegistrationId() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OAuth2DcrHttpClientTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager, ""));
	}

	@Test
	void offloadsClientRegistrationLookup() {
		var customizer = new OAuth2DcrHttpClientTransportCustomizer(authorizedClientManager,
				clientRegistrationRepository, mcpOAuth2ClientManager);
		var transportBuilder = HttpClientStreamableHttpTransport.builder("https://mcp.example.com");
		customizer.customize("my-server", transportBuilder);
		var requestCustomizer = getBuilderField(transportBuilder, "httpRequestCustomizer",
				McpAsyncHttpClientRequestCustomizer.class);
		given(clientRegistrationRepository.findByRegistrationId("my-server")).willAnswer(invocation -> {
			assertThat(Schedulers.isInNonBlockingThread()).isFalse();
			return null;
		});
		var endpoint = URI.create("https://mcp.example.com/mcp");
		var requestBuilder = HttpRequest.newBuilder(endpoint);
		var context = McpTransportContext.create(Map.of(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY,
				new TestingAuthenticationToken("user", "password"),
				AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY,
				new ServletRequestAttributes(mock(HttpServletRequest.class))));

		var result = Mono.defer(() -> {
			assertThat(Schedulers.isInNonBlockingThread()).isTrue();
			return Mono.from(requestCustomizer.customize(requestBuilder, "POST", endpoint, "{}", context));
		}).subscribeOn(Schedulers.parallel()).block(Duration.ofSeconds(5));

		assertThat(result).isSameAs(requestBuilder);
		verify(clientRegistrationRepository).findByRegistrationId("my-server");
	}

	@Nested
	class Customize {

		@Test
		@DisplayName("Sets httpRequestCustomizer and authorizationErrorHandler on the builder")
		void setsCustomizerAndErrorHandler() {
			var customizer = new OAuth2DcrHttpClientTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager);
			var builder = HttpClientStreamableHttpTransport.builder("https://mcp.example.com");

			customizer.customize("my-server", builder);

			assertThat(getBuilderField(builder, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isNotSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(getBuilderField(builder, "authorizationErrorHandler",
					McpHttpClientTransportAuthorizationErrorHandler.class))
				.isNotSameAs(McpHttpClientTransportAuthorizationErrorHandler.NOOP);
		}

		@Test
		@DisplayName("With default registration ID, applies to all transports")
		void defaultRegistrationId() {
			var customizer = new OAuth2DcrHttpClientTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager, "authserver");
			var builder1 = HttpClientStreamableHttpTransport.builder("https://mcp1.example.com");
			var builder2 = HttpClientStreamableHttpTransport.builder("https://mcp2.example.com");

			customizer.customize("server-one", builder1);
			customizer.customize("server-two", builder2);

			assertThat(getBuilderField(builder1, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isNotSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(getBuilderField(builder1, "authorizationErrorHandler",
					McpHttpClientTransportAuthorizationErrorHandler.class))
				.isNotSameAs(McpHttpClientTransportAuthorizationErrorHandler.NOOP);
			assertThat(getBuilderField(builder2, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isNotSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(getBuilderField(builder2, "authorizationErrorHandler",
					McpHttpClientTransportAuthorizationErrorHandler.class))
				.isNotSameAs(McpHttpClientTransportAuthorizationErrorHandler.NOOP);
		}

		@Test
		@DisplayName("With resolver function, uses resolved registration ID")
		void resolverFunction() {
			var mapping = Map.of("server-one", "reg-one");
			var customizer = new OAuth2DcrHttpClientTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager, mapping::get);
			var builder1 = HttpClientStreamableHttpTransport.builder("https://mcp.example.com");
			var builder2 = HttpClientStreamableHttpTransport.builder("https://mcp.example.com");

			customizer.customize("server-one", builder1);
			customizer.customize("server-three", builder2);

			assertThat(getBuilderField(builder1, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isNotSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(getBuilderField(builder1, "authorizationErrorHandler",
					McpHttpClientTransportAuthorizationErrorHandler.class))
				.isNotSameAs(McpHttpClientTransportAuthorizationErrorHandler.NOOP);
			assertThat(getBuilderField(builder2, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(getBuilderField(builder2, "authorizationErrorHandler",
					McpHttpClientTransportAuthorizationErrorHandler.class))
				.isSameAs(McpHttpClientTransportAuthorizationErrorHandler.NOOP);
		}

	}

	private static <T> T getBuilderField(HttpClientStreamableHttpTransport.Builder builder, String fieldName,
			Class<T> type) {
		Field field = ReflectionUtils.findField(builder.getClass(), fieldName);
		assertThat(field).isNotNull();
		ReflectionUtils.makeAccessible(field);
		var result = type.cast(ReflectionUtils.getField(field, builder));
		assertThat(result).isNotNull();
		return result;
	}

}
