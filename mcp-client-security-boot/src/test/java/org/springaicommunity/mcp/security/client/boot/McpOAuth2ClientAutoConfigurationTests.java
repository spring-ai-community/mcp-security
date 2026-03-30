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

import io.modelcontextprotocol.client.McpClient;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DefaultMcpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ScopeStepUpMcpOAuth2ClientManager;

import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link McpOAuth2ClientAutoConfiguration}.
 *
 * @author Daniel Garnier-Moiroux
 */
class McpOAuth2ClientAutoConfigurationTests {

	private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(McpOAuth2ClientAutoConfiguration.class));

	@Test
	void autoConfigurationRegistersProperties() {
		this.contextRunner.run(context -> {
			assertThat(context).hasSingleBean(McpOAuth2ClientProperties.class);
		});
	}

	@Test
	void defaults() {
		this.contextRunner.run(context -> {
			assertThat(context).hasSingleBean(McpMetadataDiscoveryService.class);
			assertThat(context).hasSingleBean(DynamicClientRegistrationService.class);
			assertThat(context).hasSingleBean(ClientRegistrationRepository.class)
				.getBean(ClientRegistrationRepository.class)
				.isInstanceOf(InMemoryMcpClientRegistrationRepository.class);
			assertThat(context).hasSingleBean(McpOAuth2ClientManager.class)
				.getBean(McpOAuth2ClientManager.class)
				.isInstanceOf(DefaultMcpOAuth2ClientManager.class);
		});
	}

	@Test
	void existingMcpClientRegistrationRepositoryScopeStepUp() {
		this.contextRunner.withUserConfiguration(CustomMcpClientRegistrationRepositoryConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(McpOAuth2ClientManager.class)
					.getBean(McpOAuth2ClientManager.class)
					.isInstanceOf(ScopeStepUpMcpOAuth2ClientManager.class);
			});
	}

	@Test
	void dynamicClientRegistrationDisabled() {
		this.contextRunner.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration=false")
			.run(context -> {
				assertThat(context).doesNotHaveBean(McpMetadataDiscoveryService.class);
				assertThat(context).doesNotHaveBean(DynamicClientRegistrationService.class);
			});
	}

	@Test
	void dynamicClientRegistrationDisabledScopeStepUp() {
		this.contextRunner.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration=false")
			.run(context -> {
				assertThat(context).hasSingleBean(McpOAuth2ClientManager.class)
					.getBean(McpOAuth2ClientManager.class)
					.isInstanceOf(ScopeStepUpMcpOAuth2ClientManager.class);
			});
	}

	@Test
	void dynamicClientRegistrationEnabledExplicitly() {
		this.contextRunner.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration=true")
			.run(context -> {
				assertThat(context).hasSingleBean(McpMetadataDiscoveryService.class);
				assertThat(context).hasSingleBean(DynamicClientRegistrationService.class);
			});
	}

	@Test
	void clientRegistrationRepositoryLoadsOAuth2ClientProperties() {
		this.contextRunner
			.withPropertyValues("spring.security.oauth2.client.registration.test.client-id=test-client-id",
					"spring.security.oauth2.client.registration.test.client-secret=test-client-secret",
					"spring.security.oauth2.client.registration.test.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.test.token-uri=https://example.com/oauth2/token")
			.run(context -> {
				assertThat(context).hasSingleBean(McpClientRegistrationRepository.class);
				var repo = context.getBean(McpClientRegistrationRepository.class);
				assertThat(repo.findByRegistrationId("test")).isNotNull();
				assertThat(repo.findByRegistrationId("test").getClientId()).isEqualTo("test-client-id");
			});
	}

	@Test
	void backsOffClientRegistrationRepository() {
		this.contextRunner.withUserConfiguration(CustomClientRegistrationRepositoryConfiguration.class).run(context -> {
			assertThat(context).hasSingleBean(ClientRegistrationRepository.class);
			assertThat(context).doesNotHaveBean(McpClientRegistrationRepository.class);
			assertThat(context.getBean(ClientRegistrationRepository.class))
				.isSameAs(context.getBean(CustomClientRegistrationRepositoryConfiguration.class).customRepository);
		});
	}

	@Test
	void backsOffMetadataDiscoveryService() {
		this.contextRunner.withUserConfiguration(CustomMetadataDiscoveryServiceConfiguration.class).run(context -> {
			assertThat(context).hasSingleBean(McpMetadataDiscoveryService.class);
			assertThat(context.getBean(McpMetadataDiscoveryService.class))
				.isSameAs(context.getBean(CustomMetadataDiscoveryServiceConfiguration.class).customService);
		});
	}

	@Test
	void backsOffDynamicClientRegistrationService() {
		this.contextRunner.withUserConfiguration(CustomDynamicClientRegistrationServiceConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(DynamicClientRegistrationService.class);
				assertThat(context.getBean(DynamicClientRegistrationService.class))
					.isSameAs(context.getBean(CustomDynamicClientRegistrationServiceConfiguration.class).customService);
			});
	}

	@Test
	void backsOffMcpOAuth2ClientManager() {
		this.contextRunner.withUserConfiguration(CustomMcpOAuth2ClientManagerConfiguration.class).run(context -> {
			assertThat(context).hasSingleBean(McpOAuth2ClientManager.class);
			assertThat(context).doesNotHaveBean(DefaultMcpOAuth2ClientManager.class);
			assertThat(context).doesNotHaveBean(ScopeStepUpMcpOAuth2ClientManager.class);
			assertThat(context.getBean(McpOAuth2ClientManager.class))
				.isSameAs(context.getBean(CustomMcpOAuth2ClientManagerConfiguration.class).customManager);
		});
	}

	@Test
	@SuppressWarnings("unchecked")
	void registersMcpClientTransportContextProviderCustomizer() {
		this.contextRunner.run(context -> {
			assertThat(context).hasBean("mcpClientTransportContextProviderCustomizer");
			assertThat(context).hasSingleBean(McpClientCustomizer.class);
			var customizer = (McpClientCustomizer<McpClient.SyncSpec>) context
				.getBean("mcpClientTransportContextProviderCustomizer");
			assertThat(customizer).isNotNull();
		});
	}

	@Test
	void nonServlet() {
		new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(McpOAuth2ClientAutoConfiguration.class))
			.run(context -> {
				assertThat(context).doesNotHaveBean(McpOAuth2ClientManager.class);
				assertThat(context).doesNotHaveBean(McpOAuth2ClientProperties.class);
				assertThat(context).doesNotHaveBean(McpClientRegistrationRepository.class);
			});
	}

	@Test
	void existingClientRegistrationRepository() {
		this.contextRunner.withUserConfiguration(CustomClientRegistrationRepositoryConfiguration.class).run(context -> {
			assertThat(context).doesNotHaveBean(McpOAuth2ClientManager.class);
			assertThat(context).doesNotHaveBean(DefaultMcpOAuth2ClientManager.class);
			assertThat(context).doesNotHaveBean(ScopeStepUpMcpOAuth2ClientManager.class);
		});
	}

	@Configuration
	static class CustomClientRegistrationRepositoryConfiguration {

		private final ClientRegistrationRepository customRepository = mock(ClientRegistrationRepository.class);

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return customRepository;
		}

	}

	@Configuration
	static class CustomMcpClientRegistrationRepositoryConfiguration {

		private final McpClientRegistrationRepository customRepository = mock(McpClientRegistrationRepository.class);

		@Bean
		McpClientRegistrationRepository mcpClientRegistrationRepository() {
			return customRepository;
		}

	}

	@Configuration
	static class CustomMetadataDiscoveryServiceConfiguration {

		final McpMetadataDiscoveryService customService = new McpMetadataDiscoveryService();

		@Bean
		McpMetadataDiscoveryService mcpMetadataDiscoveryService() {
			return this.customService;
		}

	}

	@Configuration
	static class CustomDynamicClientRegistrationServiceConfiguration {

		final DynamicClientRegistrationService customService = new DynamicClientRegistrationService();

		@Bean
		DynamicClientRegistrationService dynamicClientRegistrationService() {
			return this.customService;
		}

	}

	@Configuration
	static class CustomMcpOAuth2ClientManagerConfiguration {

		final McpOAuth2ClientManager customManager = mock(McpOAuth2ClientManager.class);

		@Bean
		McpOAuth2ClientManager mcpOAuth2ClientManager() {
			return this.customManager;
		}

	}

}
