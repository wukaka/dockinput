package com.nbd.dockinput.auth.client.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;

@RestController
public class ResourceController {

    @Resource
    RestTemplate restTemplate;


    @GetMapping("/server/a/res1")
    public String getServerARes1(@RegisteredOAuth2AuthorizedClient
                                         OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("http://os.com:10002/res1", oAuth2AuthorizedClient);
    }

    @GetMapping("/server/a/res2")
    public String getServerARes2(@RegisteredOAuth2AuthorizedClient
                                         OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("os.com:10002/res2", oAuth2AuthorizedClient);
    }

    private String getServer(String url, OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        // 获取 token
        String tokenValue = oAuth2AuthorizedClient.getAccessToken().getTokenValue();
        // 请求头
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + tokenValue);
        // 请求体
        HttpEntity<Object> httpEntity = new HttpEntity<>(headers);
        // 发起请求
        ResponseEntity<String> responseEntity;
        try {
            responseEntity = restTemplate.exchange(url, HttpMethod.GET, httpEntity, String.class);
        } catch (RestClientException e) {
            // e.getMessage() 信息格式：
            // 403 : "{"msg":"拒绝访问","uri":"/res2"}"
            // 解析，取出消息体 {"msg":"拒绝访问","uri":"/res2"}
            String str = e.getMessage();
            // 取两个括号中间的部分（包含两个括号）
            return str.substring(str.indexOf("{"), str.indexOf("}") + 1);
        }
        // 返回
        return responseEntity.getBody();
    }
}
