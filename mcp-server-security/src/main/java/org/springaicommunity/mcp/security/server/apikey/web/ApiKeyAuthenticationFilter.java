package org.springaicommunity.mcp.security.server.apikey.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyImpl;
import org.springaicommunity.mcp.security.server.apikey.authentication.ApiKeyAuthenticationToken;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.util.StringUtils;

public class ApiKeyAuthenticationFilter extends AuthenticationFilter {

	public static final String DEFAULT_API_KEY_HEADER = "X-API-Key";

	public ApiKeyAuthenticationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager, keyExtractorFor(DEFAULT_API_KEY_HEADER));

		setSuccessHandler(new PassthroughSuccessHandler());
		setFailureHandler(
				new AuthenticationEntryPointFailureHandler(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
	}

	private static AuthenticationConverter keyExtractorFor(String apiKeyHeader) {
		return request -> {
			String apiKey = request.getHeader(apiKeyHeader);

			if (!StringUtils.hasText(apiKey)) {
				return null;
			}

			try {
				return ApiKeyAuthenticationToken.unauthenticated(ApiKeyImpl.from(apiKey));
			}
			catch (IllegalArgumentException e) {
				throw new BadCredentialsException(e.getMessage(), e);
			}
		};

	}

	public void setApiKeyHeader(String apiKeyHeader) {
		setAuthenticationConverter(keyExtractorFor(apiKeyHeader));
	}

	private static class PassthroughSuccessHandler implements AuthenticationSuccessHandler {

		@Override
		public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
				Authentication authentication) throws IOException, ServletException {
			chain.doFilter(request, response);
		}

		@Override
		public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
				Authentication authentication) throws IOException, ServletException {
			throw new RuntimeException("Should never reach this");
		}

	}

}