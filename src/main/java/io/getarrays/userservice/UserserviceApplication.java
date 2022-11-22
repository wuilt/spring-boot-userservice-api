package io.getarrays.userservice;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.getarrays.userservice.domain.Role;
import io.getarrays.userservice.domain.User;
import io.getarrays.userservice.service.UserService;

@SpringBootApplication
public class UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}

	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
			
			userService.saveUser(new User(null, "ahmed", "elafifi", "123", new ArrayList<>()));
			userService.saveUser(new User(null, "ahmed1", "elafifi1", "123", new ArrayList<>()));
			userService.saveUser(new User(null, "ahmed2", "elafifi2", "123", new ArrayList<>()));
			userService.saveUser(new User(null, "ahmed3", "elafifi3", "123", new ArrayList<>()));
			userService.saveUser(new User(null, "ahmed4", "elafifi4", "123", new ArrayList<>()));

			userService.addRoleToUser("elafifi", "ROLE_USER");
			userService.addRoleToUser("elafifi1", "ROLE_MANAGER");
			userService.addRoleToUser("elafifi2", "ROLE_MANAGER");
			userService.addRoleToUser("elafifi3", "ROLE_ADMIN");
			userService.addRoleToUser("elafifi4", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("elafifi4", "ROLE_SUPER_ADMIN");
		};
	}
}
