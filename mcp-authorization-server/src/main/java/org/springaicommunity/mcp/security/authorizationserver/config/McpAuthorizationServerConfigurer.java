/*
 * Copyright 2025-2025 the original author or authors.
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

package org.springaicommunity.mcp.security.authorizationserver.config;

import java.util.Map;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.jspecify.annotations.Nullable;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.mcp.token.ResourceIdentifierAudienceTokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author Daniel Garnier-Moiroux
 */
public class McpAuthorizationServerConfigurer
		extends AbstractHttpConfigurer<McpAuthorizationServerConfigurer, HttpSecurity> {

	private Customizer<OAuth2AuthorizationServerConfigurer> authServerCustomizer = Customizer.withDefaults();

	public static McpAuthorizationServerConfigurer mcpAuthorizationServer() {
		return new McpAuthorizationServerConfigurer();
	}

	/**
	 * Customize the underlying Spring Security OAuth2 Authorization Server configuration,
	 * through a {@link OAuth2AuthorizationServerConfigurer}.
	 * @param oauth2AuthorizationServerConfigurerCustomizer a customizer of OAuth2
	 * Authorization Server. Defaults to a no-op {@link Customizer#withDefaults()}.
	 * @return The {@link McpAuthorizationServerConfigurer} for further configuration.
	 */
	public McpAuthorizationServerConfigurer authorizationServer(
			Customizer<OAuth2AuthorizationServerConfigurer> oauth2AuthorizationServerConfigurerCustomizer) {
		Assert.notNull(oauth2AuthorizationServerConfigurerCustomizer,
				"oauth2AuthorizationServerConfigurerCustomizer cannot be null");
		this.authServerCustomizer = oauth2AuthorizationServerConfigurerCustomizer;
		return this;
	}

	@Override
	public void init(HttpSecurity http) {
		http.authorizeHttpRequests(
				authz -> authz.withObjectPostProcessor(McpOpenClientRegistryAuthorizationManager.postProcessor()))
			.oauth2AuthorizationServer(authServer -> {
				authServer.addObjectPostProcessor(McpNoScopeClientConsentNotRequired.postProcessor());
				authServer.authorizationServerMetadataEndpoint(Customizer.withDefaults());
				OAuth2TokenGenerator<?> tokenGenerator = getTokenGenerator(http);
				authServer.tokenGenerator(tokenGenerator);
				authServer.clientRegistrationEndpoint(cr -> cr.openRegistrationAllowed(true));
				this.authServerCustomizer.customize(authServer);
			});

		// This makes Spring servers happy by ensuring that
		// NimbusJwtDecoder.withIssuerLocation(...) does not blow up on an HTTP redirect
		// to a login page.
		http.exceptionHandling(
				exc -> exc.defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.NOT_FOUND),
						PathPatternRequestMatcher.withDefaults().matcher("/.well-known/openid-configuration")));
	}

	private OAuth2TokenGenerator<?> getTokenGenerator(HttpSecurity http) {
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
		if (tokenGenerator == null) {
			tokenGenerator = getOptionalBean(http, OAuth2TokenGenerator.class);
			if (tokenGenerator == null) {
				JWKSource<SecurityContext> jwkSource = getJwkSource(http);
				JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
				jwtGenerator.setJwtCustomizer(new ResourceIdentifierAudienceTokenCustomizer());
				OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
				tokenGenerator = new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
			}

		}
		http.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
		return tokenGenerator;
	}

	/**
	 * Lifted from
	 * {@code org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2ConfigurerUtils}.
	 */
	@Nullable static JWKSource<SecurityContext> getJwkSource(HttpSecurity http) {
		JWKSource<SecurityContext> jwkSource = http.getSharedObject(JWKSource.class);
		if (jwkSource == null) {
			ResolvableType type = ResolvableType.forClassWithGenerics(JWKSource.class, SecurityContext.class);
			jwkSource = getOptionalBean(http, type);
			if (jwkSource != null) {
				http.setSharedObject(JWKSource.class, jwkSource);
			}
		}
		return jwkSource;
	}

	/**
	 * Lifted from
	 * {@code org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2ConfigurerUtils}.
	 */
	@Nullable static <T> T getOptionalBean(HttpSecurity http, Class<T> type) {
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
	 * Lifted from
	 * {@code org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2ConfigurerUtils}.
	 */
	@Nullable static <T> T getOptionalBean(HttpSecurity http, ResolvableType type) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(type);
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		return (names.length == 1) ? (T) context.getBean(names[0]) : null;
	}

}
