package com.example.jwt;

import com.example.jwt.domain.Role;
import com.example.jwt.domain.User;
import com.example.jwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService){
        return args -> {
//            userService.saveRole(new Role(null, "ROLE_USER"));
//            userService.saveRole(new Role(null, "ROLE_MANAGER"));
//            userService.saveRole(new Role(null, "ROLE_ADMIN"));
//            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
//
//            userService.saveUser(new User(null, "VuPhu", "vuphu", "1234", new ArrayList<>()));
//            userService.saveUser(new User(null, "VuPhu2002", "vuphu2002", "1234", new ArrayList<>()));
//            userService.saveUser(new User(null, "VuPhu1806", "vuphu1806", "1234", new ArrayList<>()));
//            userService.saveUser(new User(null, "VuPhuvhtb", "vuphuvhtb", "1234", new ArrayList<>()));
//
//            userService.addRoleToUser("vuphu", "ROLE_USER");
//            userService.addRoleToUser("vuphu2002", "ROLE_MANAGER");
//            userService.addRoleToUser("vuphu1806", "ROLE_ADMIN");
//            userService.addRoleToUser("vuphuvhtb", "ROLE_SUPER_ADMIN");
//            userService.addRoleToUser("vuphuvhtb", "ROLE_USER_ADMIN");
//            userService.addRoleToUser("vuphuvhtb", "ROLE_USER");
        };
    }
}
