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

package org.springaicommunity.mcp.security.client.sync.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationRequest;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2ClientConfigurer;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Configurer for OAuth2 support for MCP clients.
 *
 * @author Daniel Garnier-Moiroux
 */
public class McpClientOAuth2Configurer extends AbstractHttpConfigurer<McpClientOAuth2Configurer, HttpSecurity> {

	private static final Logger log = LoggerFactory.getLogger(McpClientOAuth2Configurer.class);

	private Customizer<OAuth2ClientConfigurer<HttpSecurity>> oauth2ClientCustomizer = Customizer.withDefaults();

	private final Map<String, String> mcpRegistrations = new HashMap<>();

	@Nullable private String baseUrl = null;

	private final boolean canListenForWebServerInitialized;

	public McpClientOAuth2Configurer() {
		this.canListenForWebServerInitialized = ClassUtils.isPresent(
				"org.springframework.boot.web.server.servlet.context.ServletWebServerInitializedEvent",
				getClass().getClassLoader());
	}

	@Override
	public void init(HttpSecurity http) {
		var clientRegistrationRepository = getClientRegistrationRepository(http);
		registerMcpClients(http, clientRegistrationRepository);

		http.oauth2Client(oauth2Client -> {
			if (clientRegistrationRepository instanceof McpClientRegistrationRepository mcpClientRegistrationRepository) {
				oauth2Client.authorizationCodeGrant(authorizationCode -> {
					var authRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
							mcpClientRegistrationRepository,
							OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
					authRequestResolver.setAuthorizationRequestCustomizer(
							mcpAuthorizationRequestCustomizer(mcpClientRegistrationRepository));

					authorizationCode.authorizationRequestResolver(authRequestResolver);
					var tokenResponseClient = new RestClientAuthorizationCodeTokenResponseClient();
					tokenResponseClient
						.addParametersConverter(mcpTokenRequestParametersConverter(mcpClientRegistrationRepository));
					authorizationCode.accessTokenResponseClient(tokenResponseClient);
				});
			}
			else {
				log.warn(
						"ClientRegistrationRepository is not of type [{}]. Instead, found bean of type [{}]. Authorization and token requests will not include a \"resource=\" parameter.",
						McpClientRegistrationRepository.class.getName(),
						clientRegistrationRepository.getClass().getName());
			}

			oauth2ClientCustomizer.customize(oauth2Client);
		});

	}

	/**
	 * Customize the underlying Spring Security OAuth2 Client configuration, through an
	 * {@link OAuth2ClientConfigurer}.
	 * @param oauth2ClientCustomizer a customizer of OAuth2 Client. Defaults to a no-op
	 * {@link Customizer#withDefaults()}
	 * @return The {@link McpClientOAuth2Configurer} for further configuration
	 */
	public McpClientOAuth2Configurer oauth2Client(
			Customizer<OAuth2ClientConfigurer<HttpSecurity>> oauth2ClientCustomizer) {
		Assert.notNull(oauth2ClientCustomizer, "oauth2ClientCustomizer cannot be null");
		this.oauth2ClientCustomizer = oauth2ClientCustomizer;
		return this;
	}

	/**
	 * Register OAuth2 Client for this given MCP Server. Note that, if no
	 * {@link #baseUrl(String)} is set, the registration will happen only after the web
	 * server starts. This is required to infer the correct base URL for all redirect URLs
	 * when dynamically registering clients. This may lead to a race-condition if an MCP
	 * Client is called before the dynamic clients are registered.
	 * @param registrationId the id used for
	 * {@link ClientRegistration#getRegistrationId()}
	 * @param mcpServerUrl the URL of the MCP server
	 * @return The {@link McpClientOAuth2Configurer} for further configuration
	 */
	public McpClientOAuth2Configurer registerMcpOAuth2Client(String registrationId, String mcpServerUrl) {
		Assert.notNull(registrationId, "registration cannot be null");
		Assert.notNull(mcpServerUrl, "mcpServerUrl cannot be null");
		this.mcpRegistrations.put(registrationId, mcpServerUrl);
		return this;
	}

	/**
	 * The base URL to be used to construct redirect URIs for dynamically registered
	 * clients. If not set, it will default to {@code http://localhost:{port}}.
	 * @param baseUrl the base URL of the application
	 * @return The {@link McpClientOAuth2Configurer} for further configuration
	 */
	public McpClientOAuth2Configurer baseUrl(String baseUrl) {
		this.baseUrl = baseUrl;
		return this;
	}

	private void registerMcpClients(HttpSecurity http, ClientRegistrationRepository repository) {
		if (this.mcpRegistrations.isEmpty()) {
			return;
		}
		if (!(repository instanceof McpClientRegistrationRepository mcpClientRegistrationRepo)) {
			throw new IllegalStateException(
					"You can only register OAuth2 Clients for MCP Servers with an McpClientRegistrationRepository. "
							+ "Found a bean of type [%s] instead. ".formatted(repository.getClass().getName())
							+ "Ensure Spring Boot is not auto-configuring a repository for you, either by disabling OAuth2ClientAutoConfiguration "
							+ "or by not using spring.security.oauth2.client.registration.* properties. "
							+ "Alternatively, consider providing your own McpClientRegistrationRepository bean.");
		}
		if (this.baseUrl != null) {
			doRegisterMcpClients(mcpClientRegistrationRepo, this.baseUrl, this.mcpRegistrations);
		}
		else if (this.canListenForWebServerInitialized) {
			var context = http.getSharedObject(ApplicationContext.class);
			if (context instanceof ConfigurableApplicationContext configurableContext) {
				registerClientsOnServerStartup(configurableContext, mcpClientRegistrationRepo, this.mcpRegistrations);
			}
			else {
				throw new IllegalStateException(
						"The application context is not an instance of ConfigurableApplicationContext. Instead, it is [%s]. Consider using a baseUrl instead of relying on server port auto-detection."
							.formatted(context.getClass().getName()));
			}
		}
		else {
			throw new IllegalStateException(
					"The application seems to not allow Spring Boot MVC application. Consider using a baseUrl instead of relying on server port auto-detection.");
		}
	}

	private static void doRegisterMcpClients(McpClientRegistrationRepository repo, String baseUrl,
			Map<String, String> registrations) {
		for (var entry : registrations.entrySet()) {
			var registration = DynamicClientRegistrationRequest.builder()
				.grantTypes(List.of(AuthorizationGrantType.AUTHORIZATION_CODE))
				.redirectUris(List.of(baseUrl + "/authorize/oauth2/code/" + entry.getKey()))
				.build();
			repo.registerMcpClient(entry.getKey(), entry.getValue(), registration);
		}
	}

	private static Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> mcpTokenRequestParametersConverter(
			McpClientRegistrationRepository mcpClientRegistrationRepository) {
		return new McpTokenRequestParametersConverter(mcpClientRegistrationRepository);
	}

	private static Consumer<OAuth2AuthorizationRequest.Builder> mcpAuthorizationRequestCustomizer(
			McpClientRegistrationRepository mcpClientRegistrationRepository) {
		return req -> {
			var baseRequest = req.build();
			var registrationIdAttr = baseRequest.getAttributes().get(OAuth2ParameterNames.REGISTRATION_ID);
			if (registrationIdAttr instanceof String registrationId) {
				req.additionalParameters(params -> params.put("resource",
						mcpClientRegistrationRepository.findResourceIdByRegistrationId(registrationId)));
			}
		};
	}

	private ClientRegistrationRepository getClientRegistrationRepository(HttpSecurity http) {
		ClientRegistrationRepository clientRegistrationRepository = http
			.getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			clientRegistrationRepository = getOptionalBean(http, ClientRegistrationRepository.class);
			if (clientRegistrationRepository == null) {
				clientRegistrationRepository = new InMemoryMcpClientRegistrationRepository(
						getDynamicClientRegistrationService(http), getMcpMetadataDiscovery(http));
			}
			http.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private McpMetadataDiscoveryService getMcpMetadataDiscovery(HttpSecurity http) {
		McpMetadataDiscoveryService discovery = http.getSharedObject(McpMetadataDiscoveryService.class);
		if (discovery == null) {
			discovery = getOptionalBean(http, McpMetadataDiscoveryService.class);
			if (discovery == null) {
				discovery = new McpMetadataDiscoveryService();
			}
			http.setSharedObject(McpMetadataDiscoveryService.class, discovery);
		}
		return discovery;
	}

	private DynamicClientRegistrationService getDynamicClientRegistrationService(HttpSecurity http) {
		DynamicClientRegistrationService clientRegistrationService = http
			.getSharedObject(DynamicClientRegistrationService.class);
		if (clientRegistrationService == null) {
			clientRegistrationService = getOptionalBean(http, DynamicClientRegistrationService.class);
			if (clientRegistrationService == null) {
				clientRegistrationService = new DynamicClientRegistrationService();
			}
			http.setSharedObject(DynamicClientRegistrationService.class, clientRegistrationService);
		}
		return clientRegistrationService;
	}

	/**
	 * Lifted from
	 * {@code org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2ConfigurerUtils}.
	 */
	@Nullable private static <T> T getOptionalBean(HttpSecurity http, Class<T> type) {
		Map<String, T> beansMap = BeanFactoryUtils
			.beansOfTypeIncludingAncestors(http.getSharedObject(ApplicationContext.class), type);
		if (beansMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
					"Expected single matching bean of type '" + type.getName() + "' but found " + beansMap.size() + ": "
							+ StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
		}
		return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
	}

	/**
	 * Delay the registration of clients until the server has started. This allows us to
	 * get the port of the running server for redirect urls.
	 */
	private static void registerClientsOnServerStartup(ConfigurableApplicationContext context,
			McpClientRegistrationRepository repo, Map<String, String> registrations) {
		context.addApplicationListener(event -> {
			if (event instanceof org.springframework.boot.web.server.servlet.context.ServletWebServerInitializedEvent webServerEvent) {
				var port = webServerEvent.getWebServer().getPort();
				var baseUrl = "http://localhost:" + port;
				doRegisterMcpClients(repo, baseUrl, registrations);
			}
		});
	}

	private static class McpTokenRequestParametersConverter
			implements Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> {

		private final McpClientRegistrationRepository mcpClientRegistrationRepository;

		public McpTokenRequestParametersConverter(McpClientRegistrationRepository mcpClientRegistrationRepository) {
			this.mcpClientRegistrationRepository = mcpClientRegistrationRepository;
		}

		@Override
		public MultiValueMap<String, String> convert(OAuth2AuthorizationCodeGrantRequest source) {
			var params = new LinkedMultiValueMap<String, String>();
			var resource = mcpClientRegistrationRepository
				.findResourceIdByRegistrationId(source.getClientRegistration().getRegistrationId());
			if (resource != null) {
				params.addIfAbsent("resource", resource);
			}
			return params;
		}

	}

	public static McpClientOAuth2Configurer mcpClientOAuth2() {
		return new McpClientOAuth2Configurer();
	}

}
