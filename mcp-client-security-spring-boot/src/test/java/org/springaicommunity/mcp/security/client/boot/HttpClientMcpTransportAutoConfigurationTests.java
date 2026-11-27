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

import java.util.Arrays;
import java.util.List;

import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.modern.client.McpClient;
import io.modelcontextprotocol.modern.client.transport.HttpClientMcpTransport;
import io.modelcontextprotocol.modern.client.transport.McpHttpAuthorizationErrorHandler;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequestCustomizer;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2HttpClientTransportCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.modern.OAuth2HttpClientMcpTransportCustomizer;

import org.springframework.ai.mcp.client.common.autoconfigure.McpClientModernAutoConfiguration;
import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.ResolvableType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link HttpClientMcpTransportAutoConfiguration}.
 *
 * @author Daniel Garnier-Moiroux
 */
class HttpClientMcpTransportAutoConfigurationTests {

	private static final ResolvableType TRANSPORT_CUSTOMIZER_CLASS = ResolvableType
		.forClassWithGenerics(McpClientCustomizer.class, HttpClientMcpTransport.Builder.class);

	private static final ResolvableType LEGACY_TRANSPORT_CUSTOMIZER_CLASS = ResolvableType
		.forClassWithGenerics(McpClientCustomizer.class, HttpClientStreamableHttpTransport.Builder.class);

	private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(McpOAuth2ClientAutoConfiguration.class,
				HttpClientMcpTransportAutoConfiguration.class));

	@Test
	void defaults() {
		this.contextRunner.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(OAuth2HttpClientMcpTransportCustomizer.class);
				assertThat(context).doesNotHaveBean("preRegisteredClientMcpTransportCustomizer");
				assertThat(getTransportCustomizers(context)).hasSize(1);
			});
	}

	@Test
	void cimdEnabledWithPreRegisteredClient() {
		this.contextRunner
			.withPropertyValues("spring.security.oauth2.client.registration.test.client-id=test-client-id",
					"spring.security.oauth2.client.registration.test.client-secret=test-client-secret",
					"spring.security.oauth2.client.registration.test.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.test.token-uri=https://example.com/oauth2/token")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(OAuth2HttpClientMcpTransportCustomizer.class);
				assertThat(context).doesNotHaveBean("preRegisteredClientMcpTransportCustomizer");
			});
	}

	@Test
	void cimdDisabledDcrEnabled() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.cimd.enabled=false",
					"spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=true")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(OAuth2HttpClientMcpTransportCustomizer.class);
				assertThat(context).doesNotHaveBean("preRegisteredClientMcpTransportCustomizer");
			});
	}

	@Test
	void dcrExplicitlyEnabled() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=true")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(OAuth2HttpClientMcpTransportCustomizer.class);
				assertThat(context).doesNotHaveBean("preRegisteredClientMcpTransportCustomizer");
			});
	}

	@Test
	void customizerConfiguresTransport() {
		this.contextRunner.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				var transportBuilder = mock(HttpClientMcpTransport.Builder.class);
				context.getBean(OAuth2HttpClientMcpTransportCustomizer.class).customize("test", transportBuilder);
				verify(transportBuilder).requestCustomizer(any(McpHttpRequestCustomizer.class));
				verify(transportBuilder).authorizationErrorHandler(any(McpHttpAuthorizationErrorHandler.class));
			});
	}

	@Test
	void customClientRegistrationRepositoryPreRegisteredCustomizer() {
		this.contextRunner.withUserConfiguration(CustomClientRegistrationRepositoryConfiguration.class).run(context -> {
			assertThat(context).doesNotHaveBean(OAuth2HttpClientMcpTransportCustomizer.class)
				.hasBean("preRegisteredClientMcpTransportCustomizer");
		});
	}

	@Test
	void preRegisteredCustomizer() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.cimd.enabled=false",
					"spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=false",
					"spring.security.oauth2.client.registration.test.client-id=test-client-id",
					"spring.security.oauth2.client.registration.test.client-secret=test-client-secret",
					"spring.security.oauth2.client.registration.test.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.test.token-uri=https://example.com/oauth2/token")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				var customizers = getTransportCustomizers(context);
				assertThat(customizers).hasSize(1);

				var transportBuilder = mock(HttpClientMcpTransport.Builder.class);
				customizers.get(0).customize("test", transportBuilder);
				verify(transportBuilder).requestCustomizer(any(McpHttpRequestCustomizer.class));
				verify(transportBuilder, never()).authorizationErrorHandler(any());
			});
	}

	@Test
	void cimdAndDcrDisabledNoRegistrationNoopCustomizer() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.cimd.enabled=false",
					"spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=false")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasBean("preRegisteredClientMcpTransportCustomizer");
				var customizers = getTransportCustomizers(context);
				assertThat(customizers).hasSize(1)
					.first()
					.satisfies(HttpClientMcpTransportAutoConfigurationTests::assertNoopCustomizer);
			});
	}

	@Test
	void multipleRegistrations() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.cimd.enabled=false",
					"spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=false",
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
				assertThat(context).doesNotHaveBean(OAuth2HttpClientMcpTransportCustomizer.class)
					.hasBean("preRegisteredClientMcpTransportCustomizer");
				var customizers = getTransportCustomizers(context);
				assertThat(customizers).hasSize(1)
					.first()
					.satisfies(HttpClientMcpTransportAutoConfigurationTests::assertNoopCustomizer);
			});
	}

	@Test
	void backsOffOAuth2HttpClientMcpTransportCustomizer() {
		this.contextRunner.withUserConfiguration(CustomOAuth2HttpClientMcpTransportCustomizerConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(OAuth2HttpClientMcpTransportCustomizer.class);
				assertThat(context.getBean(OAuth2HttpClientMcpTransportCustomizer.class)).isSameAs(context
					.getBean(CustomOAuth2HttpClientMcpTransportCustomizerConfiguration.class).customCustomizer);
			});
	}

	@Test
	void backsOffPreRegisteredClientCustomizer() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.cimd.enabled=false",
					"spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=false",
					"spring.security.oauth2.client.registration.test.client-id=test-client-id",
					"spring.security.oauth2.client.registration.test.client-secret=test-client-secret",
					"spring.security.oauth2.client.registration.test.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.test.token-uri=https://example.com/oauth2/token")
			.withUserConfiguration(CustomMcpClientCustomizerConfiguration.class)
			.run(context -> {
				var customizers = getTransportCustomizers(context);
				assertThat(customizers).hasSize(1)
					.first()
					.isSameAs(context.getBean(CustomMcpClientCustomizerConfiguration.class).customCustomizer);
			});
	}

	@Test
	void transportContextProviderCustomizer() {
		this.contextRunner.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasBean("mcpClientModernTransportContextProviderCustomizer");
				@SuppressWarnings("unchecked")
				var customizer = (McpClientCustomizer<McpClient.SyncBuilder>) context
					.getBean("mcpClientModernTransportContextProviderCustomizer");
				var clientBuilder = mock(McpClient.SyncBuilder.class);
				customizer.customize("test", clientBuilder);
				verify(clientBuilder).transportContextProvider(any(AuthenticationMcpTransportContextProvider.class));
			});
	}

	@Test
	void transportContextProviderCustomizerNotWebApplication() {
		new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(McpOAuth2ClientAutoConfiguration.class,
					HttpClientMcpTransportAutoConfiguration.class))
			.run(context -> assertThat(context).hasNotFailed()
				.doesNotHaveBean("mcpClientModernTransportContextProviderCustomizer"));
	}

	@Test
	void asyncClientType() {
		this.contextRunner.withPropertyValues("spring.ai.mcp.client.type=ASYNC")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).doesNotHaveBean(OAuth2HttpClientMcpTransportCustomizer.class)
					.doesNotHaveBean("preRegisteredClientMcpTransportCustomizer")
					.doesNotHaveBean("mcpClientModernTransportContextProviderCustomizer");
			});
	}

	@Test
	void coexistsWithLegacyTransportAutoConfiguration() {
		this.contextRunner
			.withConfiguration(AutoConfigurations.of(HttpClientStreamableHttpTransportAutoConfiguration.class))
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(OAuth2HttpClientMcpTransportCustomizer.class)
					.hasSingleBean(OAuth2HttpClientTransportCustomizer.class)
					.hasBean("mcpClientTransportContextProviderCustomizer")
					.hasBean("mcpClientModernTransportContextProviderCustomizer");
				assertThat(getTransportCustomizers(context)).hasSize(1);
				assertThat(context.getBeanNamesForType(LEGACY_TRANSPORT_CUSTOMIZER_CLASS)).hasSize(1);
			});
	}

	@Test
	void coexistsWithLegacyTransportAutoConfigurationPreRegistered() {
		this.contextRunner
			.withConfiguration(AutoConfigurations.of(HttpClientStreamableHttpTransportAutoConfiguration.class))
			.withPropertyValues("spring.ai.mcp.client.authorization.cimd.enabled=false",
					"spring.security.oauth2.client.registration.test.client-id=test-client-id",
					"spring.security.oauth2.client.registration.test.client-secret=test-client-secret",
					"spring.security.oauth2.client.registration.test.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.test.token-uri=https://example.com/oauth2/token")
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasBean("preRegisteredClientMcpTransportCustomizer")
					.hasBean("preRegisteredClientCustomizer");
			});
	}

	/**
	 * Spring AI 2.0 ships neither the modern transport, nor the modern client
	 * auto-configuration.
	 */
	@Test
	void springAi20BacksOff() {
		this.contextRunner
			.withConfiguration(AutoConfigurations.of(HttpClientStreamableHttpTransportAutoConfiguration.class))
			.withClassLoader(new FilteredClassLoader("io.modelcontextprotocol.modern.",
					McpClientModernAutoConfiguration.class.getName()))
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> {
				assertThat(context).hasNotFailed()
					.doesNotHaveBean(HttpClientMcpTransportAutoConfiguration.class)
					.hasSingleBean(OAuth2HttpClientTransportCustomizer.class)
					.hasBean("mcpClientTransportContextProviderCustomizer");
			});
	}

	/**
	 * The modern transport may be on the classpath with Spring AI 2.0, for example when
	 * the MCP SDK is upgraded on its own.
	 */
	@Test
	void modernSdkWithoutModernAutoConfigurationBacksOff() {
		this.contextRunner.withClassLoader(new FilteredClassLoader(McpClientModernAutoConfiguration.class.getName()))
			.withUserConfiguration(CustomOAuth2AuthorizedClientManagerConfiguration.class)
			.run(context -> assertThat(context).hasNotFailed()
				.doesNotHaveBean(HttpClientMcpTransportAutoConfiguration.class));
	}

	private static void assertNoopCustomizer(McpClientCustomizer<HttpClientMcpTransport.Builder> customizer) {
		var transportBuilder = mock(HttpClientMcpTransport.Builder.class);
		customizer.customize("test", transportBuilder);
		verifyNoInteractions(transportBuilder);
	}

	@SuppressWarnings("unchecked")
	private static List<McpClientCustomizer<HttpClientMcpTransport.Builder>> getTransportCustomizers(
			ApplicationContext context) {
		return Arrays.stream(context.getBeanNamesForType(TRANSPORT_CUSTOMIZER_CLASS))
			.map(name -> (McpClientCustomizer<HttpClientMcpTransport.Builder>) context.getBean(name))
			.toList();
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
	static class CustomClientRegistrationRepositoryConfiguration {

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return mock(ClientRegistrationRepository.class);
		}

	}

	@Configuration
	@Import(CustomOAuth2AuthorizedClientManagerConfiguration.class)
	static class CustomOAuth2HttpClientMcpTransportCustomizerConfiguration {

		final OAuth2HttpClientMcpTransportCustomizer customCustomizer = mock(
				OAuth2HttpClientMcpTransportCustomizer.class);

		@Bean
		OAuth2HttpClientMcpTransportCustomizer oAuth2HttpClientMcpTransportCustomizer() {
			return this.customCustomizer;
		}

	}

	@Configuration
	@Import(CustomOAuth2AuthorizedClientManagerConfiguration.class)
	static class CustomMcpClientCustomizerConfiguration {

		@SuppressWarnings("unchecked")
		final McpClientCustomizer<HttpClientMcpTransport.Builder> customCustomizer = mock(McpClientCustomizer.class);

		@Bean
		McpClientCustomizer<HttpClientMcpTransport.Builder> mcpClientCustomizer() {
			return this.customCustomizer;
		}

	}

}
