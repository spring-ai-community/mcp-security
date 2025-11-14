package org.springaicommunity.mcp.security.server.oauth2.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.oauth2.metadata.ResourceIdentifier;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;

class BearerResourceMetadataTokenAuthenticationEntryPointTest {

	private final MockHttpServletRequest request = new MockHttpServletRequest();

	private final MockHttpServletResponse response = new MockHttpServletResponse();

	private final ResourceIdentifier resourceIdentifier = new ResourceIdentifier("/mcp");

	private final BearerResourceMetadataTokenAuthenticationEntryPoint entryPoint = new BearerResourceMetadataTokenAuthenticationEntryPoint(
			resourceIdentifier);

	@Test
	void commence_ShouldAddCustomContextPath() throws Exception {
		request.setContextPath("/foo");
		request.setScheme("https");
		request.setServerName("my.host.com");
		request.setServerPort(443);
		request.setRequestURI("/foo/some/endpoint");

		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

		AuthenticationException authException = mock(AuthenticationException.class);

		entryPoint.commence(request, response, authException);

		String headerValue = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);

		assertThat(headerValue)
			.contains("Bearer resource_metadata=https://my.host.com/foo/.well-known/oauth-protected-resource/mcp");

	}

	@Test
	void commence_ShouldAddDefaultContextPath() throws Exception {
		request.setContextPath("");
		request.setScheme("https");
		request.setServerName("my.host.com");
		request.setServerPort(443);
		request.setRequestURI("/some/endpoint");

		response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

		AuthenticationException authException = mock(AuthenticationException.class);

		entryPoint.commence(request, response, authException);

		String headerValue = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);

		assertThat(headerValue)
			.contains("Bearer resource_metadata=https://my.host.com/.well-known/oauth-protected-resource/mcp");
	}

}
