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

import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.client.transport.HttpRequestSnapshot;
import io.modelcontextprotocol.common.McpTransportContext;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DcrNotSupportedException;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationRequest;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2DcrClientManager;

import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Daniel Garnier-Moiroux
 */
class OAuth2DcrSyncAuthorizationErrorHandlerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String MCP_SERVER_URL = "https://mcp.example.com/mcp";

	private static final String WWW_AUTHENTICATE_HEADER = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"";

	private final McpOAuth2DcrClientManager clientManager = mock(McpOAuth2DcrClientManager.class);

	private final DynamicClientRegistrationRequest registrationRequest = DynamicClientRegistrationRequest
		.authorizationCode("https://app.example.com/authorize/oauth2/code/" + REGISTRATION_ID);

	private final OAuth2DcrSyncAuthorizationErrorHandler handler = new OAuth2DcrSyncAuthorizationErrorHandler(
			this.clientManager, REGISTRATION_ID, MCP_SERVER_URL, this.registrationRequest);

	private final HttpRequestSnapshot request = new HttpRequestSnapshot(URI.create(MCP_SERVER_URL), "POST",
			HttpHeaders.of(Map.of(), (k, v) -> true));

	@Test
	void unauthorizedRegistersClientAndRequiresAuthorization() throws Exception {
		assertThatExceptionOfType(ClientAuthorizationRequiredException.class)
			.isThrownBy(() -> this.handler.handle(this.request, unauthorized(), McpTransportContext.EMPTY))
			.satisfies(ex -> assertThat(ex.getClientRegistrationId()).isEqualTo(REGISTRATION_ID));

		verify(this.clientManager).registerMcpClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER,
				this.registrationRequest);
	}

	@Test
	void unauthorizedWhenDcrNotSupported() throws Exception {
		doThrow(new DcrNotSupportedException("https://auth.example.com")).when(this.clientManager)
			.registerMcpClient(anyString(), anyString(), anyString(), any(DynamicClientRegistrationRequest.class));

		var handled = this.handler.handle(this.request, unauthorized(), McpTransportContext.EMPTY);

		assertThat(handled).isFalse();
	}

	private static HttpResponse.ResponseInfo unauthorized() {
		var responseInfo = mock(HttpResponse.ResponseInfo.class);
		when(responseInfo.statusCode()).thenReturn(401);
		when(responseInfo.headers())
			.thenReturn(HttpHeaders.of(Map.of("WWW-Authenticate", List.of(WWW_AUTHENTICATE_HEADER)), (k, v) -> true));
		return responseInfo;
	}

}
