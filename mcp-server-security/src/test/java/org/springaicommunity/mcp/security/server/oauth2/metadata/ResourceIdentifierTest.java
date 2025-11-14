package org.springaicommunity.mcp.security.server.oauth2.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.BDDAssertions.catchThrowable;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class ResourceIdentifierTest {

	@AfterEach
	void tearDown() {
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	void constructor_ShouldThrowException_WhenPathIsEmpty() {
		// when
		Throwable thrown = catchThrowable(() -> new ResourceIdentifier(""));

		// then
		assertThat(thrown).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("path cannot be empty");
	}

	@Test
	void getPath_ShouldReturnGivenPath() {
		// given
		var identifier = new ResourceIdentifier("/my-resource");

		// then
		assertThat(identifier.getPath()).isEqualTo("/my-resource");
	}

	@Test
	void getResource_ShouldBuildFullUrlBasedOnCurrentRequest() {
		// given
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setScheme("https");
		request.setServerName("my.host.com");
		request.setServerPort(8443);
		request.setContextPath("/foo");
		request.setRequestURI("/foo/other/path");

		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

		var identifier = new ResourceIdentifier("/mcp");

		// when
		String result = identifier.getResource();

		// then
		assertThat(result).isEqualTo("https://my.host.com:8443/foo/mcp");
	}

}