package com.nbd.dockinput.auth.client.controller;

import com.alibaba.fastjson2.JSON;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.util.*;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(Model model) {
        // 从安全上下文中获取登录信息，返回给model
        Map<String, Object> map = new HashMap<>(2);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        map.put("name", auth.getName());
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.stream().iterator();
        ArrayList<Object> authList = new ArrayList<>();
        while (iterator.hasNext()) {
            authList.add(iterator.next().getAuthority());
        }
        map.put("authorities", authList);
        model.addAttribute("user", JSON.toJSONString(map));
        return "index";
    }
}
