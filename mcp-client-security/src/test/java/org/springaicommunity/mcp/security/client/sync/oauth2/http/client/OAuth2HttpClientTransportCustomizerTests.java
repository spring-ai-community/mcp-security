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
import java.util.Map;

import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.client.transport.customizer.McpAsyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.client.transport.customizer.McpHttpClientAuthorizationErrorHandler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.ReflectionUtils;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

/**
 * @author Daniel Garnier-Moiroux
 */
class OAuth2HttpClientTransportCustomizerTests {

	private final OAuth2AuthorizedClientManager authorizedClientManager = mock(OAuth2AuthorizedClientManager.class);

	private final ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);

	private final McpOAuth2ClientManager mcpOAuth2ClientManager = mock(McpOAuth2ClientManager.class);

	@Test
	void constructorRejectsEmptyDefaultRegistrationId() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OAuth2HttpClientTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager, ""));
	}

	@Nested
	class Customize {

		@Test
		@DisplayName("Sets httpRequestCustomizer and authorizationErrorHandler on the builder")
		void setsCustomizerAndErrorHandler() {
			var customizer = new OAuth2HttpClientTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager);
			var builder = HttpClientStreamableHttpTransport.builder("https://mcp.example.com");

			customizer.customize("my-server", builder);

			assertThat(getBuilderField(builder, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isNotSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(
					getBuilderField(builder, "authorizationErrorHandler", McpHttpClientAuthorizationErrorHandler.class))
				.isNotSameAs(McpHttpClientAuthorizationErrorHandler.NOOP);
		}

		@Test
		@DisplayName("With default registration ID, applies to all transports")
		void defaultRegistrationId() {
			var customizer = new OAuth2HttpClientTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager, "authserver");
			var builder1 = HttpClientStreamableHttpTransport.builder("https://mcp1.example.com");
			var builder2 = HttpClientStreamableHttpTransport.builder("https://mcp2.example.com");

			customizer.customize("server-one", builder1);
			customizer.customize("server-two", builder2);

			assertThat(getBuilderField(builder1, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isNotSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(getBuilderField(builder1, "authorizationErrorHandler",
					McpHttpClientAuthorizationErrorHandler.class))
				.isNotSameAs(McpHttpClientAuthorizationErrorHandler.NOOP);
			assertThat(getBuilderField(builder2, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isNotSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(getBuilderField(builder2, "authorizationErrorHandler",
					McpHttpClientAuthorizationErrorHandler.class))
				.isNotSameAs(McpHttpClientAuthorizationErrorHandler.NOOP);
		}

		@Test
		@DisplayName("With resolver function, uses resolved registration ID")
		void resolverFunction() {
			var mapping = Map.of("server-one", "reg-one");
			var customizer = new OAuth2HttpClientTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager, mapping::get);
			var builder1 = HttpClientStreamableHttpTransport.builder("https://mcp.example.com");
			var builder2 = HttpClientStreamableHttpTransport.builder("https://mcp.example.com");

			customizer.customize("server-one", builder1);
			customizer.customize("server-three", builder2);

			assertThat(getBuilderField(builder1, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isNotSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(getBuilderField(builder1, "authorizationErrorHandler",
					McpHttpClientAuthorizationErrorHandler.class))
				.isNotSameAs(McpHttpClientAuthorizationErrorHandler.NOOP);
			assertThat(getBuilderField(builder2, "httpRequestCustomizer", McpAsyncHttpClientRequestCustomizer.class))
				.isSameAs(McpAsyncHttpClientRequestCustomizer.NOOP);
			assertThat(getBuilderField(builder2, "authorizationErrorHandler",
					McpHttpClientAuthorizationErrorHandler.class))
				.isSameAs(McpHttpClientAuthorizationErrorHandler.NOOP);
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
