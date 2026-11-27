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
import io.modelcontextprotocol.modern.client.transport.McpHttpRequest;
import io.modelcontextprotocol.modern.client.transport.McpHttpResponseInfo;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ClientAlreadyExistsException;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.dcr.DcrNotSupportedException;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Daniel Garnier-Moiroux
 */
class OAuth2AuthorizationErrorHandlerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String MCP_SERVER_URL = "https://mcp.example.com/mcp";

	private static final String BASE_URL = "https://app.example.com";

	private static final String WWW_AUTHENTICATE_HEADER = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"";

	private static final String INSUFFICIENT_SCOPE_HEADER = "Bearer error=\"insufficient_scope\", scope=\"mcp:write\"";

	private final McpOAuth2ClientManager clientManager = mock(McpOAuth2ClientManager.class);

	private final OAuth2AuthorizationErrorHandler handler = new OAuth2AuthorizationErrorHandler(this.clientManager,
			REGISTRATION_ID);

	private final McpHttpRequest request = mock(McpHttpRequest.class);

	OAuth2AuthorizationErrorHandlerTests() {
		when(this.request.uri()).thenReturn(URI.create(MCP_SERVER_URL));
		this.handler.setFallbackBaseUrl(BASE_URL + "/");
	}

	@Test
	void unauthorizedRegistersClientAndRequiresAuthorization() throws Exception {
		assertThatExceptionOfType(ClientAuthorizationRequiredException.class)
			.isThrownBy(() -> this.handler.handle(this.request, response(401, WWW_AUTHENTICATE_HEADER),
					McpTransportContext.EMPTY))
			.satisfies(ex -> assertThat(ex.getClientRegistrationId()).isEqualTo(REGISTRATION_ID));

		verify(this.clientManager).registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);
	}

	@Test
	void unauthorizedUsesBaseUrlFromServletRequest() throws Exception {
		var servletRequest = new MockHttpServletRequest("GET", "/ctx/some/path");
		servletRequest.setScheme("https");
		servletRequest.setServerName("servlet.example.com");
		servletRequest.setServerPort(443);
		servletRequest.setContextPath("/ctx");
		var context = McpTransportContext
			.create(Map.of(AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY,
					new ServletRequestAttributes(servletRequest)));

		assertThatExceptionOfType(ClientAuthorizationRequiredException.class)
			.isThrownBy(() -> this.handler.handle(this.request, response(401, WWW_AUTHENTICATE_HEADER), context));

		verify(this.clientManager).registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER,
				"https://servlet.example.com/ctx");
	}

	@Test
	void unauthorizedWithoutBaseUrl() {
		var handler = new OAuth2AuthorizationErrorHandler(this.clientManager, REGISTRATION_ID);

		var handled = handler.handle(this.request, response(401, WWW_AUTHENTICATE_HEADER), McpTransportContext.EMPTY);

		assertThat(handled).isFalse();
		verifyNoInteractions(this.clientManager);
	}

	@Test
	void unauthorizedWhenRegistrationNotSupported() throws Exception {
		doThrow(new DcrNotSupportedException("https://auth.example.com")).when(this.clientManager)
			.registerClient(anyString(), anyString(), anyString(), anyString());

		var handled = this.handler.handle(this.request, response(401, WWW_AUTHENTICATE_HEADER),
				McpTransportContext.EMPTY);

		assertThat(handled).isFalse();
	}

	@Test
	void unauthorizedWhenClientAlreadyExists() throws Exception {
		doThrow(new ClientAlreadyExistsException(REGISTRATION_ID)).when(this.clientManager)
			.registerClient(anyString(), anyString(), anyString(), anyString());

		var handled = this.handler.handle(this.request, response(401, WWW_AUTHENTICATE_HEADER),
				McpTransportContext.EMPTY);

		assertThat(handled).isFalse();
	}

	@Test
	void forbiddenUpdatesScopesAndRequiresAuthorization() {
		when(this.clientManager.updateScopes(REGISTRATION_ID, INSUFFICIENT_SCOPE_HEADER)).thenReturn(true);

		assertThatExceptionOfType(ClientAuthorizationRequiredException.class).isThrownBy(() -> this.handler
			.handle(this.request, response(403, INSUFFICIENT_SCOPE_HEADER), McpTransportContext.EMPTY));
	}

	@Test
	void forbiddenWithoutNewScopes() {
		var handled = this.handler.handle(this.request, response(403, INSUFFICIENT_SCOPE_HEADER),
				McpTransportContext.EMPTY);

		assertThat(handled).isFalse();
	}

	@Test
	void withoutWwwAuthenticateHeader() {
		var response = McpHttpResponseInfo.of(401, HttpHeaders.of(Map.of(), (k, v) -> true));

		var handled = this.handler.handle(this.request, response, McpTransportContext.EMPTY);

		assertThat(handled).isFalse();
		verifyNoInteractions(this.clientManager);
	}

	private static McpHttpResponseInfo response(int status, String wwwAuthenticateHeader) {
		return McpHttpResponseInfo.of(status,
				HttpHeaders.of(Map.of("WWW-Authenticate", List.of(wwwAuthenticateHeader)), (k, v) -> true));
	}

}
