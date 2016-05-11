package com.xiaofong.shiro.spring;

import java.util.Date;

import org.apache.shiro.authz.annotation.RequiresRoles;

public class MyService {
	
	// 使用 shiro 的注解来进行权限的保护.
	@RequiresRoles({ "admin" })
	public void test() {
		System.out.println("test method : " + new Date());
	}

}
