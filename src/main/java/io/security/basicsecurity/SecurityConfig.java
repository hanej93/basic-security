package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

import jakarta.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.builder()
			.username("user")
			.password("{noop}1234")
			.roles("USER")
			.build();

		UserDetails sys = User.builder()
			.username("sys")
			.password("{noop}1234")
			.roles("SYS")
			.build();

		UserDetails admin = User.builder()
			.username("admin")
			.password("{noop}1234")
			.roles("ADMIN", "SYS", "USER")
			.build();

		return new InMemoryUserDetailsManager( user, sys, admin );
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
				authorizationManagerRequestMatcherRegistry
					.requestMatchers("/user").hasRole("USER")
					.requestMatchers("/admin/pay").hasRole("ADMIN")
					.requestMatchers("/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
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
					.userDetailsService(userDetailsService());
			});

		http
			.sessionManagement(httpSecuritySessionManagementConfigurer -> {
				httpSecuritySessionManagementConfigurer
					// .sessionFixation().changeSessionId() // 기본값
					// .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // 기본값
					.maximumSessions(1)
					.maxSessionsPreventsLogin(false);
			});

		return http.build();
	}

}
