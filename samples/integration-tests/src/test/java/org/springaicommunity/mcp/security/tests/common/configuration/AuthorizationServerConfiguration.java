package org.springaicommunity.mcp.security.tests.common.configuration;

import org.springaicommunity.mcp.security.tests.AllowAllCorsConfigurationSource;
import org.springaicommunity.mcp.security.tests.common.server.AuthorizationServer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.experimental.boot.server.exec.CommonsExecWebServerFactoryBean;
import org.springframework.experimental.boot.test.context.DynamicPortUrl;
import static org.springframework.experimental.boot.server.exec.MavenClasspathEntry.springBootStarter;

@Configuration
public class AuthorizationServerConfiguration {

	@Bean
	@DynamicPortUrl(name = "authorization.server.url")
	static CommonsExecWebServerFactoryBean authorizationServer() {
		// The properties file is inferred from the bean name, here it's in
		// resources/testjars/authorizationServer
		return CommonsExecWebServerFactoryBean.builder()
			.useGenericSpringBootMain()
			.setAdditionalBeanClassNames(AuthorizationServer.class.getName())
			.classpath((classpath) -> classpath.entries(springBootStarter("oauth2-authorization-server"))
				.classes(AuthorizationServer.class)
				.classes(AllowAllCorsConfigurationSource.class));
	}

}
