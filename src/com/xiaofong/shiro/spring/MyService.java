package com.xiaofong.shiro.spring;

import java.util.Date;

import org.apache.shiro.authz.annotation.RequiresRoles;

public class MyService {
	
	// ʹ�� shiro ��ע��������Ȩ�޵ı���.
	@RequiresRoles({ "admin" })
	public void test() {
		System.out.println("test method : " + new Date());
	}

}
