package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final UserDetailsService userDetailsService;

	public SecurityConfig(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

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

		http
			.logout(httpSecurityLogoutConfigurer -> {
				httpSecurityLogoutConfigurer
					.logoutUrl("/logout")
					.logoutSuccessUrl("/login")
					.addLogoutHandler((request, response, authentication) -> {
						HttpSession session = request.getSession();
						session.invalidate();
					})
					.logoutSuccessHandler((request, response, authentication) -> {
						response.sendRedirect("/login");
					})
					.deleteCookies("remember-me");
			});

		http
			.rememberMe(httpSecurityRememberMeConfigurer -> {
				httpSecurityRememberMeConfigurer
					.rememberMeParameter("remember")
					.tokenValiditySeconds(3600)
					.userDetailsService(userDetailsService);
			});

		http
			.sessionManagement(httpSecuritySessionManagementConfigurer -> {
				httpSecuritySessionManagementConfigurer
					// .sessionFixation().changeSessionId() // 기본값
					.maximumSessions(1)
					.maxSessionsPreventsLogin(false);
			});

		return http.build();
	}

}
