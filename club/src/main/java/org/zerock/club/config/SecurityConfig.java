package org.zerock.club.config;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zerock.club.security.filter.ApiCheckFilter;
import org.zerock.club.security.filter.ApiLoginFilter;
import org.zerock.club.security.handler.ApiLoginFailHandler;
import org.zerock.club.security.handler.ClubLoginSuccessHandler;
import org.zerock.club.security.service.ClubUserDetailsService;
import org.zerock.club.security.util.JWTUtil;

@Configuration
@Log4j2
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ClubUserDetailsService userDetailsService;

    @Bean
    PasswordEncoder passwordEncoder(){

        return new BCryptPasswordEncoder();
    }

    //새로 추가
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //http.authorizeRequests()
        //        .antMatchers("/sample/all").permitAll()
        //        .antMatchers("/sample/member").hasRole("USER");

        http.formLogin();
        http.csrf().disable();
        http.logout();
        http.oauth2Login().successHandler(successHandler());
        http.rememberMe().tokenValiditySeconds(60*60*24*7).userDetailsService(userDetailsService);

        http.addFilterBefore(apiCheckFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(apiLoginFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public ClubLoginSuccessHandler successHandler(){
        return new ClubLoginSuccessHandler(passwordEncoder());
    }

    @Bean
    public ApiCheckFilter apiCheckFilter() {
        return new ApiCheckFilter("/notes/**/*", jwtUtil());
    }

    @Bean
    public ApiLoginFilter apiLoginFilter() throws Exception {

        ApiLoginFilter apiLoginFilter = new ApiLoginFilter("/api/login", jwtUtil());
        apiLoginFilter.setAuthenticationManager(authenticationManager());

        apiLoginFilter.setAuthenticationFailureHandler(new ApiLoginFailHandler());

        return apiLoginFilter;
    }

    @Bean
    public JWTUtil jwtUtil(){
        return new JWTUtil();
    }

    //@Override
    //protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //사용자 계정은 user1
    //    auth.inMemoryAuthentication().withUser("user1")
        //1111패스워드 인코딩 결과
    //    .password("$2a$10$g0KCQ2qGRELr19VUuWCkU.p/eX5O1huX.aM88TG2hL1IUYh1zPXs2")
    //    .roles("USER");
    //}

}
