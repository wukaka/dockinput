package com.nbd.dockinput.ncm.config;


import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@ConditionalOnBean(JwtDecoder.class)
@Configuration(proxyBeanMethods = false)
public class OAuth2ResourceServerConfig {

    /**
     * 资源管理器配置
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
        // 拒绝访问处理器 401
        SimpleAccessDeniedHandler accessDeniedHandler = new SimpleAccessDeniedHandler();
        // 认证失败处理器 403
        SimpleAuthenticationEntryPoint authenticationEntryPoint = new SimpleAuthenticationEntryPoint();
        http
                // security的session生成策略改为security不主动创建session即STALELESS
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // 对 /res1 的请求，需要 SCOPE_read 权限
                .authorizeRequests()
                .antMatchers("/res1").hasAnyAuthority("SCOPE_read", "SCOPE_all")
                .antMatchers("/res2").hasAnyAuthority("SCOPE_write1", "SCOPE_all")
                // 其余请求都需要认证
                .anyRequest().authenticated()
                .and()
                // 异常处理
                .exceptionHandling(configurer -> configurer
                        // 拒绝访问
                        .accessDeniedHandler(accessDeniedHandler)
                        // 认证失败
                        .authenticationEntryPoint(authenticationEntryPoint)
                )
                // 资源服务
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .accessDeniedHandler(accessDeniedHandler)
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .jwt()
                );

        return http.build();


    }
}
