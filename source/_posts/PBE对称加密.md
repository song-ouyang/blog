---
title: PBE对称加密
date: 2022-3-12 11:38:26
categories: 
- "小组件" 
- "工具" 
tags: 
- 工具
- JAVA
description: 搭建的一个小的PBE对称加密
---


# PBE对称加密

### PBE

​    PBE算法是一种基于口令的加密算法，其特点在于口令是由用户自己掌握的，采用随机数杂凑多重加密等方法保证数据的安全性。 既然PBE算法使用我们较为常用的对称加密算法，那就无法回避密钥的问题。口令并不能替代密钥，密钥是经过加密算法计算得来的，但是口令本身不可能很长看，单纯的口令很容易通过穷举攻击方式破译，这就引入了“盐”。盐能阻止字典攻击或预先计算的攻击，它本身是一个随机信息，相同的随机信息极不可能使用两次。将盐附加在口令上，通过消息摘要算法经过迭代计算获得构建密钥/初始化向量的基本材料，使得破译的难度加大。



![img](http://uploadphoto.oys68.cn/photo/iYbVchZDyNxse1waKMAJazgs936TAm6u4Vj49ede.png)

1)       由消息传递双方约定口令，这里由甲方构建口令。

2)       由口令构建者发布口令，即本系统的服务器将口令发送给系统的客户端使用者

3)       由口令构建者构建本次消息传递使用的盐，这里由甲方（本系统）构建盐

4)       由消息发送方使用口令、盐对数据加密，这里由甲方对数据加密

5)       由消息发送者将盐、加密数据放松给消息接收者，这里由甲方将盐、加密数据发送给乙方

6)       由消息接收方使用盐、口令对加密数据解密，这里由乙方完成数据解密

###### Controller层

```
import com.it.result.CommonResult;
import com.it.service.DataImplService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class UserController {


    @Autowired
    private DataImplService dataImplService;

    @RequestMapping("/insert")
    public CommonResult insert(@RequestParam String data,
                                 @RequestParam String password) {
        return dataImplService.insert(data,password);
    }



    @RequestMapping("/output1")
    public CommonResult output(@RequestParam String data,
                               @RequestParam String password
    ) {
        return dataImplService.output1(data,password);
    }


    @RequestMapping("/alloutput")
    public CommonResult alloutput(@RequestBody Map map) {
        return dataImplService.alloutput(map);
    }



}
```

###### service层

```
import com.it.result.CommonResult;

import java.util.Map;

public interface DataImplService {

    CommonResult insert(String data,String password);

    CommonResult output1(String data, String password);

    CommonResult alloutput(Map map);

}
```

###### service层实现类

```
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.it.mapper.DataMapper;
import com.it.result.CommonResult;
import com.it.service.DataImplService;
import com.it.util.PBE;
import lombok.SneakyThrows;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class DataServiceImpl implements DataImplService {


    @Autowired
    private DataMapper dataMapper;

    // 加密
    @SneakyThrows
    @Override
    public CommonResult insert(String data, String password) {
        byte[] input = data.getBytes();
        // 初始化盐
        byte[] salt = PBE.initSalt();
        // 加密
        byte[] data1 = PBE.encrypt(input, password, salt);
        System.err.println("加密后data字符串\t" + Base64.getEncoder().encodeToString(data1));
        byte[] output = PBE.decrypt(data1,password,salt);
        String outputStr = new String(output);
        System.err.println("加密后字符串\t" + outputStr);
        dataMapper.addData(data,Base64.getEncoder().encodeToString(data1),password,Base64.getEncoder().encodeToString(salt));
        return new CommonResult<>(200, "加密成功",Base64.getEncoder().encodeToString(data1));
    }

    // 解密
    @SneakyThrows
    public CommonResult output1(String data, String password) {
        String salt=dataMapper.selectSalt(data,password);
        if(salt == null || salt == "")
        {
            return new CommonResult<>(500, "解密失败","密码或密钥错误");
        }
        byte[] data1 = Base64.getDecoder().decode(data);
        byte[] salt1 = Base64.getDecoder().decode(salt);
        byte[] output = PBE.decrypt(data1,password,salt1);
        String outputStr = new String(output);
        return new CommonResult<>(200, "解密成功",outputStr);
    }

    // 解密
    @SneakyThrows
    @Override
    public CommonResult alloutput(Map map) {
        List<String> list = (List) map.get("list");
        ArrayList<String> arr = new ArrayList<String> ();
        for (int i = 0; i < list.size(); i++) {
            Object lo = list.get(i);
            Map entry = (Map) lo;
            String data = (String) entry.get("data");
            String password = (String) entry.get("password");
          //  System.out.println(data + " " + password);
            String salt = dataMapper.selectSalt(data, password);
            System.out.println(salt);
            if (salt == null || salt == "") {
                return new CommonResult<>(500, "解密失败,密钥或密文错误");
            }
            byte[] data1 = Base64.getDecoder().decode(data);
            byte[] salt1 = Base64.getDecoder().decode(salt);
            byte[] output = PBE.decrypt(data1, password, salt1);
            String outputStr = new String(output);
            arr.add(outputStr);
        }
        return new CommonResult<>(200, "解密成功",arr);
    }


}
```

###### dao层

```
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Mapper
@Repository
public interface DataMapper {

   void addData(String text, String data, String password, String salt);

   String selectSalt(String data, String password);
}
```

###### xml

```
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.it.mapper.DataMapper">

    <select id="selectSalt" resultType="String" >
        select  salt from data where data=#{data} and password=#{password}
    </select>

    <insert id="addData" parameterType="Data">
        insert into data (text,data,password,salt) values(#{text},#{data},#{password},#{salt})
    </insert>
</mapper>
```

具体可以访问链接

[song-ouyang/springboot-PBE: 一个基于springboot的PBE加密 (github.com)](https://github.com/song-ouyang/springboot-PBE)
