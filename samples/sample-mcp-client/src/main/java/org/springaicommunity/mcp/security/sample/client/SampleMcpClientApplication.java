package org.springaicommunity.mcp.security.sample.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = { UserDetailsServiceAutoConfiguration.class })
public class SampleMcpClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(SampleMcpClientApplication.class, args);
	}

}
