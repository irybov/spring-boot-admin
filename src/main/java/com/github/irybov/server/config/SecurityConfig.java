package com.github.irybov.server.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
    protected void configure(HttpSecurity http) throws Exception {
	 
        SavedRequestAwareAuthenticationSuccessHandler successHandler 
            = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        successHandler.setDefaultTargetUrl("/");

        http
        	.authorizeHttpRequests(urlConfig -> urlConfig
    	            .antMatchers("/login").permitAll()
    	            .antMatchers("/assets/**", "/actuator/**").hasRole("ADMIN")
    	            .anyRequest().authenticated())
            .formLogin(login -> login
            		.loginPage("/login")
            		.successHandler(successHandler))
            .logout(logout -> logout
            		.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
    	            .invalidateHttpSession(true)
    	            .clearAuthentication(true)
    	            .deleteCookies("JSESSIONID")
    	            .logoutSuccessUrl("/login"))
	        .httpBasic(Customizer.withDefaults())
//	            .and()
            .csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .ignoringAntMatchers("/instances", "/instances/*", "/actuator/**");
    }
	
}
