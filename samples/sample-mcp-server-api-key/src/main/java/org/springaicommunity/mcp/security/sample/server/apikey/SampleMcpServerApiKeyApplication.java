package org.springaicommunity.mcp.security.sample.server.apikey;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class SampleMcpServerApiKeyApplication {

	public static void main(String[] args) {
		SpringApplication.run(SampleMcpServerApiKeyApplication.class, args);
	}

}
