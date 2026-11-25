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

package org.springaicommunity.mcp.security.client.sync.oauth2.registration.dcr;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ClientAlreadyExistsException;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DelegatingMcpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.CimdNotSupportedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Daniel Garnier-Moiroux
 */
class DelegatingMcpOAuth2ClientManagerTests {

	private static final String REGISTRATION_ID = "test-registration";

	private static final String MCP_SERVER_URL = "https://mcp.example.com/mcp";

	private static final String WWW_AUTHENTICATE_HEADER = "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"";

	private static final String BASE_URL = "https://app.example.com";

	private static final String ISSUER_URL = "https://auth.example.com";

	private final McpOAuth2ClientManager first = mock(McpOAuth2ClientManager.class);

	private final McpOAuth2ClientManager second = mock(McpOAuth2ClientManager.class);

	private final DelegatingMcpOAuth2ClientManager manager = new DelegatingMcpOAuth2ClientManager(this.first,
			this.second);

	@Test
	void registersWithFirstManager() throws Exception {
		this.manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);

		verify(this.first).registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);
		verifyNoInteractions(this.second);
	}

	@Test
	void registersWithNextManagerWhenNotSupported() throws Exception {
		doThrow(new CimdNotSupportedException(ISSUER_URL)).when(this.first)
			.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);

		this.manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);

		verify(this.second).registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);
	}

	@Test
	void throwsLastExceptionWhenNoManagerSupportsAuthorizationServer() throws Exception {
		var cimdNotSupported = new CimdNotSupportedException(ISSUER_URL);
		var dcrNotSupported = new DcrNotSupportedException(ISSUER_URL);
		doThrow(cimdNotSupported).when(this.first)
			.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);
		doThrow(dcrNotSupported).when(this.second)
			.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);

		assertThatThrownBy(
				() -> this.manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL))
			.isSameAs(dcrNotSupported)
			.hasSuppressedException(cimdNotSupported);
	}

	@Test
	void throwsWhenClientAlreadyExists() throws Exception {
		var alreadyExists = new ClientAlreadyExistsException(REGISTRATION_ID);
		doThrow(alreadyExists).when(this.first)
			.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL);

		assertThatThrownBy(
				() -> this.manager.registerClient(REGISTRATION_ID, MCP_SERVER_URL, WWW_AUTHENTICATE_HEADER, BASE_URL))
			.isSameAs(alreadyExists);
		verifyNoInteractions(this.second);
	}

	@Test
	void updatesScopesWithFirstManagerThatUpdatesThem() {
		when(this.second.updateScopes(REGISTRATION_ID, WWW_AUTHENTICATE_HEADER)).thenReturn(true);

		assertThat(this.manager.updateScopes(REGISTRATION_ID, WWW_AUTHENTICATE_HEADER)).isTrue();

		verify(this.first).updateScopes(REGISTRATION_ID, WWW_AUTHENTICATE_HEADER);
	}

	@Test
	void doesNotUpdateScopesWhenNoManagerUpdatesThem() {
		assertThat(this.manager.updateScopes(REGISTRATION_ID, WWW_AUTHENTICATE_HEADER)).isFalse();
	}

	@Test
	void requiresDelegates() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DelegatingMcpOAuth2ClientManager(List.of()));
	}

}
