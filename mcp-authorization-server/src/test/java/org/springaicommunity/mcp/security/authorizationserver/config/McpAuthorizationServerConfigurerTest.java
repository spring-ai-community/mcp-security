package org.springaicommunity.mcp.security.authorizationserver.config;

import java.util.UUID;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer.mcpAuthorizationServer;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

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
	void dcrEndpointIsOpen() {
		var dcrRequest = """
				{
					"redirect_uris": ["https://example.com/oauth2/callback"]
				}""";
		var resp = this.mvc.post()
			.uri("/oauth2/register")
			.contentType(MediaType.APPLICATION_JSON)
			.with(csrf())
			.content(dcrRequest)
			.exchange();
		assertThat(resp.getResponse().getStatus()).isEqualTo(201);
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebMvc
	@EnableWebSecurity
	static class TestConfig {

		private static final ImmutableSecret<SecurityContext> SECRET = new ImmutableSecret<>(
				"0558BC36-378D-4809-A551-E61F3B8894B9-8ECA8B16-D07E-4856-9564-50637494E51A".getBytes());

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) {
			http.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults())
				.with(mcpAuthorizationServer(), mcpAuthzServer -> {
					mcpAuthzServer.dynamicClientRegistration(true);
					mcpAuthzServer.authorizationServer(authzServer -> {
						// usually provided as a Boot bean from properties
						authzServer.authorizationServerSettings(AuthorizationServerSettings.builder().build());
					});
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

		// bypass the need for an RSA asymmetric key in tests
		@Bean
		JWKSource<SecurityContext> jwkSource() {
			return new ImmutableSecret<>(SECRET.getSecretKey());
		}

		@Bean
		public JwtDecoder jwtDecoder() {
			return NimbusJwtDecoder.withSecretKey(SECRET.getSecretKey()).macAlgorithm(MacAlgorithm.HS512).build();
		}

	}

}
