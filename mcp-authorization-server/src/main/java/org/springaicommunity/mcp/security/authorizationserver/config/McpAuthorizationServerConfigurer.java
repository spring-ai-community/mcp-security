package org.springaicommunity.mcp.security.authorizationserver.config;

import java.util.Map;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2ClientRegistrationEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.ResourceIdentifierAudienceTokenCustomizer;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.authorizationServer;

/**
 * @author Daniel Garnier-Moiroux
 */
public class McpAuthorizationServerConfigurer
		extends AbstractHttpConfigurer<McpAuthorizationServerConfigurer, HttpSecurity> {

	public static McpAuthorizationServerConfigurer mcpAuthorizationServer() {
		return new McpAuthorizationServerConfigurer();
	}

	@Override
	public void init(HttpSecurity http) throws Exception {
		http.with(authorizationServer(), authServer -> {
			authServer.authorizationServerMetadataEndpoint(
					authorizationServerMetadataEndpoint -> authorizationServerMetadataEndpoint
						.authorizationServerMetadataCustomizer(authorizationServerMetadataCustomizer()));
			OAuth2TokenGenerator<?> tokenGenerator = getTokenGenerator(http);
			authServer.tokenGenerator(tokenGenerator);
		});
		http.with(new OAuth2ClientRegistrationEndpointConfigurer(), withDefaults());
		http.csrf(csrf -> csrf.ignoringRequestMatchers(
				OAuth2ClientRegistrationEndpointConfigurer.OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI));

		// This makes Spring servers happy by ensuring that
		// NimbusJwtDecoder.withIssuerLocation(...) does not blow up on an HTTP redirect
		// to a login page.
		http.exceptionHandling(
				exc -> exc.defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.NOT_FOUND),
						PathPatternRequestMatcher.withDefaults().matcher("/.well-known/openid-configuration")));
	}

	private static Consumer<OAuth2AuthorizationServerMetadata.Builder> authorizationServerMetadataCustomizer() {
		return (builder) -> {
			AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
			String issuer = authorizationServerContext.getIssuer();

			String clientRegistrationEndpoint = UriComponentsBuilder.fromUriString(issuer)
				.path(OAuth2ClientRegistrationEndpointConfigurer.OAUTH2_CLIENT_REGISTRATION_ENDPOINT_URI)
				.build()
				.toUriString();

			builder.clientRegistrationEndpoint(clientRegistrationEndpoint);
		};
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
	static JWKSource<SecurityContext> getJwkSource(HttpSecurity http) {
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
	static <T> T getOptionalBean(HttpSecurity http, Class<T> type) {
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
	static <T> T getOptionalBean(HttpSecurity http, ResolvableType type) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(type);
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		return (names.length == 1) ? (T) context.getBean(names[0]) : null;
	}

}
