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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client.modern;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.modern.client.transport.HttpClientMcpTransport;
import io.modelcontextprotocol.modern.client.transport.McpHttpAuthorizationErrorHandler;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequest;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequestCustomizer;
import io.modelcontextprotocol.modern.client.transport.McpHttpResponseInfo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Daniel Garnier-Moiroux
 */
class OAuth2HttpClientMcpTransportCustomizerTests {

	private static final String BASE_URL = "https://app.example.com/ctx";

	private static final String MCP_SERVER_URL = "https://mcp.example.com/mcp";

	private static final String WWW_AUTHENTICATE_HEADER = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"";

	private final OAuth2AuthorizedClientManager authorizedClientManager = mock(OAuth2AuthorizedClientManager.class);

	private final ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);

	private final McpOAuth2ClientManager mcpOAuth2ClientManager = mock(McpOAuth2ClientManager.class);

	@Test
	void constructorRejectsEmptyDefaultRegistrationId() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OAuth2HttpClientMcpTransportCustomizer(this.authorizedClientManager,
					this.clientRegistrationRepository, this.mcpOAuth2ClientManager, ""));
	}

	@Nested
	class Customize {

		@Test
		@DisplayName("Adds a request customizer and sets an authorization error handler on the builder")
		void setsCustomizerAndErrorHandler() {
			var customizer = new OAuth2HttpClientMcpTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager);
			var builder = mock(HttpClientMcpTransport.Builder.class);

			customizer.customize("my-server", builder);

			verify(builder).requestCustomizer(any(McpHttpRequestCustomizer.class));
			verify(builder).authorizationErrorHandler(any(McpHttpAuthorizationErrorHandler.class));
		}

		@Test
		@DisplayName("By default, uses the transport name as the registration ID")
		void transportNameAsRegistrationId() {
			var customizer = new OAuth2HttpClientMcpTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager);
			var builder = mock(HttpClientMcpTransport.Builder.class);

			customizer.customize("my-server", builder);

			assertRegistersClient(builder, "my-server");
		}

		@Test
		@DisplayName("With default registration ID, applies to all transports")
		void defaultRegistrationId() {
			var customizer = new OAuth2HttpClientMcpTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager, "authserver");
			var builder1 = mock(HttpClientMcpTransport.Builder.class);
			var builder2 = mock(HttpClientMcpTransport.Builder.class);

			customizer.customize("server-one", builder1);
			customizer.customize("server-two", builder2);

			verify(builder1).requestCustomizer(any(McpHttpRequestCustomizer.class));
			assertRegistersClient(builder1, "authserver");
			verify(builder2).requestCustomizer(any(McpHttpRequestCustomizer.class));
			assertRegistersClient(builder2, "authserver");
		}

		@Test
		@DisplayName("With resolver function, uses resolved registration ID")
		void resolverFunction() {
			var mapping = Map.of("server-one", "reg-one");
			var customizer = new OAuth2HttpClientMcpTransportCustomizer(authorizedClientManager,
					clientRegistrationRepository, mcpOAuth2ClientManager, mapping::get);
			var builder1 = mock(HttpClientMcpTransport.Builder.class);
			var builder2 = mock(HttpClientMcpTransport.Builder.class);

			customizer.customize("server-one", builder1);
			customizer.customize("server-three", builder2);

			verify(builder1).requestCustomizer(any(McpHttpRequestCustomizer.class));
			assertRegistersClient(builder1, "reg-one");
			verifyNoInteractions(builder2);
		}

		/**
		 * Run the error handler set on the builder for a 401, and check that it registers
		 * the client with the expected registration ID, and the base URL of the servlet
		 * request in the context.
		 */
		private void assertRegistersClient(HttpClientMcpTransport.Builder builder, String registrationId) {
			var captor = ArgumentCaptor.forClass(McpHttpAuthorizationErrorHandler.class);
			verify(builder).authorizationErrorHandler(captor.capture());
			var request = mock(McpHttpRequest.class);
			when(request.uri()).thenReturn(URI.create(MCP_SERVER_URL));
			var response = McpHttpResponseInfo.of(401, HttpHeaders
				.of(Map.of("WWW-Authenticate", List.of(WWW_AUTHENTICATE_HEADER)), (name, value) -> true));

			assertThatExceptionOfType(ClientAuthorizationRequiredException.class)
				.isThrownBy(() -> captor.getValue().handle(request, response, servletRequestContext()).block())
				.satisfies(ex -> assertThat(ex.getClientRegistrationId()).isEqualTo(registrationId));
			try {
				verify(mcpOAuth2ClientManager).registerClient(registrationId, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER,
						BASE_URL);
			}
			catch (Exception ex) {
				throw new AssertionError(ex);
			}
			clearInvocations(mcpOAuth2ClientManager);
		}

		private static McpTransportContext servletRequestContext() {
			var servletRequest = new MockHttpServletRequest("POST", "/ctx/chat");
			servletRequest.setScheme("https");
			servletRequest.setServerName("app.example.com");
			servletRequest.setServerPort(443);
			servletRequest.setContextPath("/ctx");
			return McpTransportContext.create(Map.of(AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY,
					new ServletRequestAttributes(servletRequest)));
		}

	}

}
