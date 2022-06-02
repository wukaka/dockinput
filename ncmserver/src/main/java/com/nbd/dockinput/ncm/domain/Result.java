package com.nbd.dockinput.ncm.domain;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Setter;

import java.time.LocalDateTime;


@Data
@Setter(AccessLevel.NONE)
public class Result {
    /**
     * 返回码
     */
    private Integer code;
    /**
     * 数据
     */
    private Object data;
    /**
     * 时间
     */
    private LocalDateTime time;


    public Result(Integer code, Object data) {
        this.code = code;
        this.data = data;
        this.time = LocalDateTime.now();
    }
}
