package org.springaicommunity.mcp.security.server.oauth2.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springaicommunity.mcp.security.server.oauth2.metadata.ResourceIdentifier;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

class BearerResourceMetadataTokenAuthenticationEntryPointTest {

	private HttpServletRequest request;

	private HttpServletResponse response;

	private ResourceIdentifier resourceIdentifier;

	private BearerResourceMetadataTokenAuthenticationEntryPoint entryPoint;

	@BeforeEach
	void setUp() {
		request = mock(HttpServletRequest.class);
		response = mock(HttpServletResponse.class);
		resourceIdentifier = mock(ResourceIdentifier.class);
		when(resourceIdentifier.getPath()).thenReturn("/mcp");
		entryPoint = new BearerResourceMetadataTokenAuthenticationEntryPoint(resourceIdentifier);
	}

	@Test
	void commence_ShouldAddCustomContextPath() throws Exception {
		when(request.getContextPath()).thenReturn("/foo");
		when(request.getScheme()).thenReturn("https");
		when(request.getServerName()).thenReturn("my.host.com");
		when(request.getServerPort()).thenReturn(443);
		when(request.getRequestURI()).thenReturn("/foo/some/endpoint");
		when(request.getQueryString()).thenReturn(null);

		when(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).thenReturn("Bearer");

		AuthenticationException authException = mock(AuthenticationException.class);

		entryPoint.commence(request, response, authException);

		ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
		verify(response).setHeader(eq(HttpHeaders.WWW_AUTHENTICATE), captor.capture());

		String headerValue = captor.getValue();
		assertThat(headerValue)
			.contains("Bearer resource_metadata=https://my.host.com/foo/.well-known/oauth-protected-resource/mcp");
	}

	@Test
	void commence_ShouldAddDefaultContextPath() throws Exception {
		when(request.getContextPath()).thenReturn("/");
		when(request.getScheme()).thenReturn("https");
		when(request.getServerName()).thenReturn("my.host.com");
		when(request.getServerPort()).thenReturn(443);
		when(request.getRequestURI()).thenReturn("/some/endpoint");
		when(request.getQueryString()).thenReturn(null);

		when(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).thenReturn("Bearer");

		AuthenticationException authException = mock(AuthenticationException.class);

		entryPoint.commence(request, response, authException);

		ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
		verify(response).setHeader(eq(HttpHeaders.WWW_AUTHENTICATE), captor.capture());

		String headerValue = captor.getValue();
		assertThat(headerValue)
			.contains("Bearer resource_metadata=https://my.host.com/.well-known/oauth-protected-resource/mcp");
	}

}
