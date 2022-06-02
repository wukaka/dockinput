package com.nbd.dockinput.auth.client.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        // 任何请求都需要认证
        http.authorizeRequests(requests -> requests.anyRequest().authenticated())
                // oauth2三方登录
                .oauth2Login(Customizer.withDefaults())
                .oauth2Client()
                .and()
                .logout();
        return http.build();
    }

    @Bean
    public RestTemplate oauth2ClientRestTemplate(RestTemplateBuilder restTemplateBuilder) {
        return restTemplateBuilder.build();
    }
}
