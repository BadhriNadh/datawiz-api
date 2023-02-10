package com.groupten.datawiz;

import com.groupten.datawiz.model.User;
import com.groupten.datawiz.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class DatawizApplication {

	public static void main(String[] args) {
		SpringApplication.run(DatawizApplication.class, args);
	}

//	@Bean
//	CommandLineRunner commandLineRunner (UserRepository userRepository, PasswordEncoder passwordEncoder) {
//		return args -> {
//			userRepository.save(new User("userN", passwordEncoder.encode("1234")));
//		};
//	}

}
