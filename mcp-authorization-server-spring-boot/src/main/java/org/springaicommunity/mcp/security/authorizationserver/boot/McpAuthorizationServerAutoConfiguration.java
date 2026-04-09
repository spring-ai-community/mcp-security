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

package org.springaicommunity.mcp.security.authorizationserver.boot;

import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.web.servlet.ConditionalOnDefaultWebSecurity;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer;
import static org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer.mcpAuthorizationServer;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * {@link AutoConfiguration} for MCP Authorization Server security. Provides a default
 * {@link SecurityFilterChain} that secures all endpoints and applies the
 * {@code mcpAuthorizationServer} configurer, which sets up dynamic client registration,
 * resource-identifier-aware token generation, and other MCP-specific authorization server
 * features.
 * <p>
 * Heavily inspired by {@code OAuth2AuthorizationServerWebSecurityConfiguration}.
 *
 * @author Daniel Garnier-Moiroux
 */
@AutoConfiguration(before = OAuth2AuthorizationServerAutoConfiguration.class)
@ConditionalOnDefaultWebSecurity
@EnableConfigurationProperties({ OAuth2AuthorizationServerProperties.class,
		McpOAuth2AuthorizationServerProperties.class })
class McpAuthorizationServerAutoConfiguration {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			McpOAuth2AuthorizationServerProperties properties,
			ObjectProvider<Customizer<McpAuthorizationServerConfigurer>> mcpCustomizers) {
		return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
			.with(mcpAuthorizationServer(), mcp -> {
				mcp.dynamicClientRegistration(properties.getDynamicClientRegistration().isEnabled());
				mcp.authorizationServer(authzServer -> {
					http.securityMatcher(new OrRequestMatcher(authzServer.getEndpointsMatcher(),
							PathPatternRequestMatcher.withDefaults().matcher("/.well-known/openid-configuration")));
				});
				mcpCustomizers.orderedStream().forEach(customizer -> customizer.customize(mcp));
			})
			.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"), createRequestMatcher()))
			.build();
	}

	@Bean
	@Order(SecurityFilterProperties.BASIC_AUTH_ORDER)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
		http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated()).formLogin(withDefaults());
		return http.build();
	}

	@Bean
	@ConditionalOnMissingBean
	@ConditionalOnProperty(prefix = McpOAuth2AuthorizationServerProperties.CONFIG_PREFIX,
			name = "dynamic-client-registration.enabled", havingValue = "true", matchIfMissing = true)
	RegisteredClientRepository dcrRegisteredClientRepository(OAuth2AuthorizationServerProperties properties) {
		var clients = new OAuth2AuthorizationServerPropertiesMapper(properties).asRegisteredClients();
		// default generated client: the repository cannot be empty, but we support DCR
		// so we should be able to add clients after it's wired. This client cannot be
		// used, because BASIC auth requires a non-empty client_id and client_secret,
		// and this one has no client_secret.
		var defaultClient = RegisteredClient.withId("default-auto-registered-client")
			.clientName("default-auto-registered-client")
			.clientId("default")
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.build();
		return new InMemoryRegisteredClientRepository(clients.isEmpty() ? List.of(defaultClient) : clients);
	}

	private static RequestMatcher createRequestMatcher() {
		MediaTypeRequestMatcher requestMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		requestMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
		return requestMatcher;
	}

}
