package com.vehiclestore;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// Main entry point of Spring Boot application
// @SpringBootApplication combines:
//   @Configuration - Can define @Bean methods
//   @EnableAutoConfiguration - Auto-configure based on dependencies
//   @ComponentScan - Scan for @Component, @Service, @Repository, @Controller in this package

// To disable security for testing (uncomment if needed):
// @SpringBootApplication(exclude = {
// 		org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration.class,
// 		org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration.class
// })

@SpringBootApplication
public class DemoApplication {

	// Application starts here
	// SpringApplication.run() bootstraps the application:
	// 1. Create ApplicationContext
	// 2. Scan components
	// 3. Start embedded Tomcat server
	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

}
