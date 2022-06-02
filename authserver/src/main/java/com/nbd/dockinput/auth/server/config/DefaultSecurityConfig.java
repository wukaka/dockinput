package com.nbd.dockinput.auth.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;

@EnableWebSecurity
public class DefaultSecurityConfig {

    /**
     * 请求授权
     *
     * @param security
     * @return
     * @throws Exception
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity security) throws Exception {
        security.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated()).formLogin()
                .and().logout()
                .and().oauth2ResourceServer().jwt();
        return security.build();
    }

    /**
     * 模拟用户
     *
     * @return
     */
    @Bean
    UserDetailsService users() {
        UserDetails user = User.builder()
                .username("admin")
                .password("123456")
                .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder()::encode)
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    /**
     * jwt解码器
     * @return
     * @throws Exception
     */
    @Bean
    JwtDecoder jwtDecoder() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("x.509");
        ClassPathResource resource = new ClassPathResource("myjks.cer");
        Certificate certificate = certificateFactory.generateCertificate(resource.getInputStream());
        RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }
}
