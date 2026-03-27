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

package org.springaicommunity.mcp.security.client.boot;

import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2HttpClientTransportCustomizer;

import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link HttpClientStreamableHttpTransportAutoconfiguration}.
 *
 * @author Daniel Garnier-Moiroux
 */
class HttpClientStreamableHttpTransportAutoconfigurationTests {

	private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(McpOAuth2ClientAutoconfiguration.class,
				HttpClientStreamableHttpTransportAutoconfiguration.class));

	@Test
	void defaults() {
		this.contextRunner.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(OAuth2HttpClientTransportCustomizer.class);
				assertThat(context).doesNotHaveBean("preRegisteredClientCustomizer");
			});
	}

	@Test
	@SuppressWarnings("unchecked")
	void preRegisteredCustomizer() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration=false",
					"spring.security.oauth2.client.registration.test.client-id=test-client-id",
					"spring.security.oauth2.client.registration.test.client-secret=test-client-secret",
					"spring.security.oauth2.client.registration.test.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.test.token-uri=https://example.com/oauth2/token")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).doesNotHaveBean(OAuth2HttpClientTransportCustomizer.class)
					.hasBean("preRegisteredClientCustomizer");
				var customizer = (McpClientCustomizer<HttpClientStreamableHttpTransport.Builder>) context
					.getBean("preRegisteredClientCustomizer");
				var transportBuilder = mock(HttpClientStreamableHttpTransport.Builder.class);
				customizer.customize("test", transportBuilder);
				verify(transportBuilder)
					.httpRequestCustomizer(any(OAuth2AuthorizationCodeSyncHttpRequestCustomizer.class));
			});
	}

	@Test
	@SuppressWarnings("unchecked")
	void dcrDisabledNoRegistrationNoopCustomizer() {
		this.contextRunner.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration=false")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).doesNotHaveBean(OAuth2HttpClientTransportCustomizer.class);
				assertThat(context).hasBean("preRegisteredClientCustomizer");
				var customizer = (McpClientCustomizer<HttpClientStreamableHttpTransport.Builder>) context
					.getBean("preRegisteredClientCustomizer");
				var transportBuilder = mock(HttpClientStreamableHttpTransport.Builder.class);
				customizer.customize("test", transportBuilder);
				verifyNoInteractions(transportBuilder);
			});
	}

	@Test
	@SuppressWarnings("unchecked")
	void multipleRegistrations() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration=false",
					"spring.security.oauth2.client.registration.first.client-id=first-client-id",
					"spring.security.oauth2.client.registration.first.client-secret=first-client-secret",
					"spring.security.oauth2.client.registration.first.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.first.token-uri=https://example.com/oauth2/token",
					"spring.security.oauth2.client.registration.second.client-id=second-client-id",
					"spring.security.oauth2.client.registration.second.client-secret=second-client-secret",
					"spring.security.oauth2.client.registration.second.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.second.token-uri=https://example.com/oauth2/token")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).doesNotHaveBean(OAuth2HttpClientTransportCustomizer.class)
					.hasBean("preRegisteredClientCustomizer");
				var customizer = (McpClientCustomizer<HttpClientStreamableHttpTransport.Builder>) context
					.getBean("preRegisteredClientCustomizer");
				var transportBuilder = mock(HttpClientStreamableHttpTransport.Builder.class);
				customizer.customize("test", transportBuilder);
				verifyNoInteractions(transportBuilder);
			});
	}

	@Test
	void dcrExplicitlyEnabled() {
		this.contextRunner.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration=true")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(OAuth2HttpClientTransportCustomizer.class);
				assertThat(context).doesNotHaveBean("preRegisteredClientCustomizer");
			});
	}

	@Test
	void noClientRegistrationRepository() {
		this.contextRunner.withUserConfiguration(CustomClientRegistrationRepositoryConfiguration.class).run(context -> {
			assertThat(context).doesNotHaveBean(OAuth2HttpClientTransportCustomizer.class);
			assertThat(context).doesNotHaveBean("preRegisteredClientCustomizer");
		});
	}

	@Test
	void backsOffOAuth2HttpClientTransportCustomizer() {
		this.contextRunner.withUserConfiguration(CustomOAuth2HttpClientTransportCustomizerConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(OAuth2HttpClientTransportCustomizer.class);
				assertThat(context.getBean(OAuth2HttpClientTransportCustomizer.class)).isSameAs(
						context.getBean(CustomOAuth2HttpClientTransportCustomizerConfiguration.class).customCustomizer);
			});
	}

	@Test
	@SuppressWarnings("unchecked")
	void backsOffPreRegisteredClientCustomizer() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration=false",
					"spring.security.oauth2.client.registration.test.client-id=test-client-id",
					"spring.security.oauth2.client.registration.test.client-secret=test-client-secret",
					"spring.security.oauth2.client.registration.test.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.test.token-uri=https://example.com/oauth2/token")
			.withUserConfiguration(CustomMcpClientCustomizerConfiguration.class)
			.run(context -> {
				assertThat(context).doesNotHaveBean(OAuth2HttpClientTransportCustomizer.class);
				var customizer = (McpClientCustomizer<HttpClientStreamableHttpTransport.Builder>) context
					.getBean("mcpClientCustomizer");
				assertThat(customizer)
					.isSameAs(context.getBean(CustomMcpClientCustomizerConfiguration.class).customCustomizer);
			});
	}

	@Configuration
	static class CustomOAuth2AuthorizedClientManagerConfiguration {

		@Bean
		OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager() {
			return mock(OAuth2AuthorizedClientManager.class);
		}

	}

	@Configuration
	@Import(CustomOAuth2AuthorizedClientManagerConfiguration.class)
	static class CustomOAuth2HttpClientTransportCustomizerConfiguration {

		final OAuth2HttpClientTransportCustomizer customCustomizer = mock(OAuth2HttpClientTransportCustomizer.class);

		@Bean
		OAuth2HttpClientTransportCustomizer oAuth2HttpClientTransportCustomizer() {
			return this.customCustomizer;
		}

	}

	@Configuration
	@Import(CustomOAuth2AuthorizedClientManagerConfiguration.class)
	static class CustomMcpClientCustomizerConfiguration {

		@SuppressWarnings("unchecked")
		final McpClientCustomizer<HttpClientStreamableHttpTransport.Builder> customCustomizer = mock(
				McpClientCustomizer.class);

		@Bean
		McpClientCustomizer<HttpClientStreamableHttpTransport.Builder> mcpClientCustomizer() {
			return this.customCustomizer;
		}

	}

	@Configuration
	@Import(CustomOAuth2AuthorizedClientManagerConfiguration.class)
	static class CustomClientRegistrationRepositoryConfiguration {

		private final ClientRegistrationRepository customRepository = mock(ClientRegistrationRepository.class);

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return customRepository;
		}

	}

}
