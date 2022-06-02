package com.nbd.dockinput.ncm.api;

import com.alibaba.fastjson2.JSON;
import com.nbd.dockinput.ncm.domain.Result;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/res1")
    public String getRes1() {
        return JSON.toJSONString(new Result(200, "服务A -> 资源1"));
    }

    @GetMapping("/res2")
    public String getRes2() {
        return JSON.toJSONString(new Result(200, "服务A -> 资源2"));
    }
}
