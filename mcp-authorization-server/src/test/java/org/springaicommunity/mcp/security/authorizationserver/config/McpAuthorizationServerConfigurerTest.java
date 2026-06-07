package org.springaicommunity.mcp.security.authorizationserver.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.assertj.MvcTestResult;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer.mcpAuthorizationServer;
import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR;

@ExtendWith(SpringExtension.class)
@ContextConfiguration
@WebAppConfiguration
class McpAuthorizationServerConfigurerTest {

	@Autowired
	WebApplicationContext wac;

	private MockMvcTester mvc;

	@BeforeEach
	void setUp() {
		this.mvc = MockMvcTester.from(wac,
				builder -> builder.apply(SecurityMockMvcConfigurers.springSecurity()).build());
	}

	@Test
	void wellKnownOpenIdConfigurationReturns404InsteadOfRedirect() {
		var resp = this.mvc.get().uri("/.well-known/openid-configuration");
		assertThat(resp).hasStatus(HttpStatus.NOT_FOUND);
	}

	@Test
	void anyRequestRedirectsToLogin() {
		var resp = this.mvc.get()
			.uri("/some-protected-endpoint")
			.accept(org.springframework.http.MediaType.TEXT_HTML)
			.exchange();
		assertThat(resp).hasStatus(HttpStatus.FOUND);
		assertThat(resp.getResponse().getHeader("Location")).endsWith("/login");
	}

	@Test
	void metadataHasRegistrationAndCimd() {
		var resp = this.mvc.get()
			.uri("/.well-known/oauth-authorization-server")
			.contentType(MediaType.APPLICATION_JSON)
			.exchange();
		assertThat(resp).bodyJson()
			.hasPathSatisfying("$.registration_endpoint",
					v -> assertThat(v).isEqualTo("http://localhost/oauth2/register"))
			.hasPathSatisfying("$.client_id_metadata_document_supported", v -> assertThat(v).asBoolean().isTrue());
	}

	@Test
	void dcrEndpointIsOpen() {
		var dcrRequest = """
				{
					"redirect_uris": ["https://example.com/oauth2/callback"]
				}""";
		var resp = registerClient(dcrRequest);
		assertThat(resp.getResponse().getStatus()).isEqualTo(201);
	}

	@Test
	void stackingAuthzServerCustomizers() {
		var authzServerCustomizerCalled = wac.getBean("authzServerCustomizationCount", AtomicInteger.class);

		assertThat(authzServerCustomizerCalled.get()).isEqualTo(2);
	}

	@Test
	void tokenIsCustomized() {
		var resp = this.mvc.post()
			.uri("/oauth2/token")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.content("grant_type=client_credentials")
			.headers(h -> h.setBasicAuth("test-client", "test-secret"))
			.exchange();

		assertThat(resp).hasStatus(HttpStatus.OK);
		var mapper = JsonMapper.builder().build();
		var response = mapper.readValue(resp.getResponse().getContentAsByteArray(), Map.class);
		var accessToken = response.get("access_token");
		assertThat(accessToken).isNotNull();

		var token = accessToken.toString();
		var encodedPayload = token.split("\\.")[1];
		var decoded = Base64.getUrlDecoder().decode(encodedPayload);
		var thingy = mapper.readValue(decoded, Map.class);

		assertThat(thingy).containsEntry("one", "one").containsEntry("two", "two");
	}

	@Test
	void dynamicClientRegistrationSucceeds() {
		var resp = registerClient("""
				{
					"redirect_uris": ["https://example.com/callback"],
					"scope": "test.read test.write"
				}
				""");
		assertThat(resp).hasStatus(HttpStatus.CREATED);
	}

	@Test
	void dynamicClientRegistrationFailsValidation() {
		var invalidRedirectUri = """
				{
					"redirect_uris": ["https://example.com/callback#invalid-fragment"]
				}
				""";
		var invalidScope = """
				{
					"redirect_uris": ["https://example.com/callback"],
					"scope": "admin.scope"
				}
				""";
		assertThat(registerClient(invalidRedirectUri)).hasStatus(HttpStatus.BAD_REQUEST)
			.bodyJson()
			.extractingPath("error")
			.isEqualTo("invalid_redirect_uri");
		assertThat(registerClient(invalidScope)).hasStatus(HttpStatus.BAD_REQUEST)
			.bodyJson()
			.extractingPath("error")
			.isEqualTo("invalid_scope");
	}

	private MvcTestResult registerClient(String clientRegistration) {
		return this.mvc.post()
			.uri("/oauth2/register")
			.contentType(MediaType.APPLICATION_JSON)
			.content(clientRegistration)
			.exchange();
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebMvc
	@EnableWebSecurity
	static class TestConfig {

		private static final ImmutableSecret<SecurityContext> SECRET = new ImmutableSecret<>(
				"0558BC36-378D-4809-A551-E61F3B8894B9-8ECA8B16-D07E-4856-9564-50637494E51A".getBytes());

		private static final Consumer<OAuth2ClientRegistrationAuthenticationContext> clientRegistrationValidator = DEFAULT_REDIRECT_URI_VALIDATOR
			.andThen(ctx -> {
				OAuth2ClientRegistrationAuthenticationToken registration = ctx.getAuthentication();
				var scopes = registration.getClientRegistration().getScopes();
				if (scopes != null && scopes.stream().anyMatch(s -> !s.startsWith("test."))) {
					throw new OAuth2AuthenticationException(
							new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE, "Scopes must start with 'test.'",
									"https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2"));
				}
			});

		@Bean
		AtomicInteger authzServerCustomizationCount() {
			return new AtomicInteger(0);
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, AtomicInteger authzServerCustomizationCount) {
			http.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults())
				.csrf(CsrfConfigurer::disable)
				.with(mcpAuthorizationServer(), mcpAuthzServer -> {
					mcpAuthzServer.dynamicClientRegistration(true);
					mcpAuthzServer.authorizationServer(authzServer -> authzServerCustomizationCount.incrementAndGet());
					mcpAuthzServer.authorizationServer(authzServer -> {
						// usually provided as a Boot bean from properties
						authzServer.authorizationServerSettings(AuthorizationServerSettings.builder().build());
					});
					mcpAuthzServer.authorizationServer(authzServer -> authzServerCustomizationCount.incrementAndGet());
					mcpAuthzServer.cimd(true);
					mcpAuthzServer.dynamicClientRegistrationValidator(clientRegistrationValidator);
				});
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();
			return new InMemoryUserDetailsManager(user);
		}

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("test-client")
				.clientSecret("{noop}test-secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("test.scope")
				.build();
			return new InMemoryRegisteredClientRepository(registeredClient);
		}

		@Bean
		public JWKSource<SecurityContext> jwkSource() {
			KeyPair keyPair = generateRsaKey();
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
			JWKSet jwkSet = new JWKSet(rsaKey);
			return new ImmutableJWKSet<>(jwkSet);
		}

		@Bean
		public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		private static KeyPair generateRsaKey() {
			KeyPair keyPair;
			try {
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
				keyPairGenerator.initialize(2048);
				keyPair = keyPairGenerator.generateKeyPair();
			}
			catch (Exception ex) {
				throw new IllegalStateException(ex);
			}
			return keyPair;
		}

		@Bean
		OAuth2TokenCustomizer<JwtEncodingContext> firstCustomizer() {
			return jwt -> jwt.getClaims().claim("one", "one");
		}

		@Bean
		OAuth2TokenCustomizer<JwtEncodingContext> secondCustomizer() {
			return jwt -> jwt.getClaims().claim("two", "two");

		}

	}

}
