package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
				authorizationManagerRequestMatcherRegistry
					.anyRequest().authenticated();
			});

		http
			.formLogin(httpSecurityFormLoginConfigurer -> {
				httpSecurityFormLoginConfigurer
					// .loginPage("/loginPage")
					.defaultSuccessUrl("/")
					.failureUrl("/login")
					.usernameParameter("userId")
					.passwordParameter("passwd")
					.loginProcessingUrl("/login_proc")
					.successHandler((request, response, authentication) -> {
						System.out.println("authentication = " + authentication.getName());
						response.sendRedirect("/");
					})
					.failureHandler((request, response, exception) -> {
						System.out.println("exception = " + exception.getMessage());
						response.sendRedirect("/login");
					})
					.permitAll();
			});

		return http.build();
	}

}
