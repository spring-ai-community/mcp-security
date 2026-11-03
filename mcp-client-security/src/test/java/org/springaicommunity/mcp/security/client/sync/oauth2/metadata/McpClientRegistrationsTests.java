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

package org.springaicommunity.mcp.security.client.sync.oauth2.metadata;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class McpClientRegistrationsTests {

	private static final String ISSUER = "https://auth.example.com";

	private static final String OAUTH_METADATA = """
			{
				"issuer": "%s",
				"authorization_endpoint": "%1$s/authorize",
				"token_endpoint": "%1$s/token",
				"registration_endpoint": "%1$s/register",
				"response_types_supported": ["code"],
				"token_endpoint_auth_methods_supported": ["none"]
			}
			""";

	private static final String OIDC_METADATA = """
			{
				"issuer": "%s",
				"authorization_endpoint": "%1$s/oidc/authorize",
				"token_endpoint": "%1$s/oidc/token",
				"jwks_uri": "%1$s/jwks",
				"userinfo_endpoint": "%1$s/userinfo",
				"response_types_supported": ["code"],
				"subject_types_supported": ["public"],
				"id_token_signing_alg_values_supported": ["RS256"]
			}
			""";

	private final RestClient.Builder restClientBuilder = RestClient.builder();

	private final MockRestServiceServer server = MockRestServiceServer.bindTo(this.restClientBuilder).build();

	private final RestClient restClient = this.restClientBuilder.build();

	@Test
	void rfc8414MetadataWinsOverOpenIdConfiguration() {
		this.server.expect(requestTo(ISSUER + "/.well-known/oauth-authorization-server"))
			.andRespond(withSuccess(OAUTH_METADATA.formatted(ISSUER), MediaType.APPLICATION_JSON));

		var registration = McpClientRegistrations.fromIssuerLocation(ISSUER, this.restClient)
			.clientId("client")
			.build();

		this.server.verify();
		var provider = registration.getProviderDetails();
		assertThat(provider.getAuthorizationUri()).isEqualTo(ISSUER + "/authorize");
		assertThat(provider.getTokenUri()).isEqualTo(ISSUER + "/token");
		assertThat(provider.getIssuerUri()).isEqualTo(ISSUER);
		assertThat(provider.getConfigurationMetadata()).containsEntry("registration_endpoint", ISSUER + "/register");
		assertThat(registration.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
	}

	@Test
	void missingRfc8414MetadataFallsBackToOpenIdConfiguration() {
		this.server.expect(requestTo(ISSUER + "/.well-known/oauth-authorization-server"))
			.andRespond(withStatus(HttpStatus.NOT_FOUND));
		this.server.expect(requestTo(ISSUER + "/.well-known/openid-configuration"))
			.andRespond(withSuccess(OIDC_METADATA.formatted(ISSUER), MediaType.APPLICATION_JSON));

		var registration = McpClientRegistrations.fromIssuerLocation(ISSUER, this.restClient)
			.clientId("client")
			.build();

		this.server.verify();
		var provider = registration.getProviderDetails();
		assertThat(provider.getAuthorizationUri()).isEqualTo(ISSUER + "/oidc/authorize");
		assertThat(provider.getJwkSetUri()).isEqualTo(ISSUER + "/jwks");
		assertThat(provider.getUserInfoEndpoint().getUri()).isEqualTo(ISSUER + "/userinfo");
	}

	@Test
	void issuerWithPathTriesTheSpecOrder() {
		var issuer = ISSUER + "/tenant1";
		this.server.expect(requestTo(ISSUER + "/.well-known/oauth-authorization-server/tenant1"))
			.andRespond(withStatus(HttpStatus.NOT_FOUND));
		this.server.expect(requestTo(ISSUER + "/.well-known/openid-configuration/tenant1"))
			.andRespond(withStatus(HttpStatus.NOT_FOUND));
		this.server.expect(requestTo(issuer + "/.well-known/openid-configuration"))
			.andRespond(withSuccess(OIDC_METADATA.formatted(issuer), MediaType.APPLICATION_JSON));

		var registration = McpClientRegistrations.fromIssuerLocation(issuer, this.restClient)
			.clientId("client")
			.build();

		this.server.verify();
		assertThat(registration.getProviderDetails().getIssuerUri()).isEqualTo(issuer);
	}

	@Test
	void invalidOpenIdConfigurationIsSkipped() {
		var issuer = ISSUER + "/tenant1";
		this.server.expect(requestTo(ISSUER + "/.well-known/oauth-authorization-server/tenant1"))
			.andRespond(withStatus(HttpStatus.NOT_FOUND));
		// no jwks_uri: not a valid OpenID Connect document
		this.server.expect(requestTo(ISSUER + "/.well-known/openid-configuration/tenant1"))
			.andRespond(withSuccess(OAUTH_METADATA.formatted(issuer), MediaType.APPLICATION_JSON));
		this.server.expect(requestTo(issuer + "/.well-known/openid-configuration"))
			.andRespond(withSuccess(OIDC_METADATA.formatted(issuer), MediaType.APPLICATION_JSON));

		var registration = McpClientRegistrations.fromIssuerLocation(issuer, this.restClient)
			.clientId("client")
			.build();

		this.server.verify();
		assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo(issuer + "/jwks");
	}

	@Test
	void issuerMismatchThrows() {
		this.server.expect(requestTo(ISSUER + "/.well-known/oauth-authorization-server"))
			.andRespond(withSuccess(OAUTH_METADATA.formatted("https://other.example.com"), MediaType.APPLICATION_JSON));
		this.server.expect(requestTo(ISSUER + "/.well-known/openid-configuration"))
			.andRespond(withStatus(HttpStatus.NOT_FOUND));

		assertThatThrownBy(() -> McpClientRegistrations.fromIssuerLocation(ISSUER, this.restClient))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("does not match");
		this.server.verify();
	}

}
