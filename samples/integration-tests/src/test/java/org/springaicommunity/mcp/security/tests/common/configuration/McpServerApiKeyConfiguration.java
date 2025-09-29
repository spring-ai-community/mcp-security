package org.springaicommunity.mcp.security.tests.common.configuration;

import java.util.List;

import org.eclipse.aether.repository.RemoteRepository;
import org.springaicommunity.mcp.security.server.apikey.ApiKey;
import org.springaicommunity.mcp.security.server.config.McpApiKeyConfigurer;
import org.springaicommunity.mcp.security.tests.AllowAllCorsConfigurationSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.experimental.boot.server.exec.CommonsExecWebServerFactoryBean;
import org.springframework.experimental.boot.server.exec.MavenClasspathEntry;
import org.springframework.experimental.boot.server.exec.ResourceClasspathEntry;
import org.springframework.experimental.boot.test.context.DynamicPortUrl;
import static org.springframework.experimental.boot.server.exec.MavenClasspathEntry.springBootStarter;

@Configuration
public class McpServerApiKeyConfiguration {

	@Bean
	@DynamicPortUrl(name = "mcp.server.url")
	public CommonsExecWebServerFactoryBean mcpServer(@Value("${mcp.server.protocol}") String mcpServerProtocol,
			@Value("${mcp.server.class}") String mcpServerClass) {
		// The properties file is inferred from the bean name, here it's in
		// resources/testjars/mcpServer
		String mcpServerResourceName = mcpServerClass.replace('.', '/') + ".class";
		return CommonsExecWebServerFactoryBean.builder()
			.useGenericSpringBootMain()
			.setAdditionalBeanClassNames(mcpServerClass)
			.systemProperties(props -> props.putIfAbsent("spring.ai.mcp.server.protocol", mcpServerProtocol))
			.classpath((classpath) -> classpath
				.entries(springBootStarter("web"), springBootStarter("security"), springAiStarter("mcp-server-webmvc"))
				.entries(new ResourceClasspathEntry(mcpServerResourceName, mcpServerResourceName))
				.classes(AllowAllCorsConfigurationSource.class)
				.classes(McpApiKeyConfigurer.class)
				.scan(ApiKey.class));
	}

	public static MavenClasspathEntry springAiStarter(String starterName) {
		return new MavenClasspathEntry("org.springframework.ai:spring-ai-starter-" + starterName + ":1.1.0-M2",
				List.of(newCentralRepository(), newSpringMilestoneRepository(), newSpringSnapshotRepository()));
	}

	private static RemoteRepository newCentralRepository() {
		return new RemoteRepository.Builder("central", "default", "https://repo.maven.apache.org/maven2/").build();
	}

	private static RemoteRepository newSpringSnapshotRepository() {
		return new RemoteRepository.Builder("spring-snapshot", "default", "https://repo.spring.io/snapshot/").build();
	}

	private static RemoteRepository newSpringMilestoneRepository() {
		return new RemoteRepository.Builder("spring-milestone", "default", "https://repo.spring.io/milestone/").build();
	}

}
