package com.xiaofong.shiro.spring;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ShiroHandler {

	@Autowired
	private MyService myService;

	@RequestMapping("/testShiroAnnotation")
	public String testShiroAnnotation() {
		System.out.println("testShiroAnnotation ...");
		myService.test();

		return "success";
	}

	@RequestMapping("/shiro-login")
	public String login(@RequestParam("username") String username, @RequestParam("password") String password) {
		// 获取当前的 Subject 实例. 通过 SecurityUtils.getSubject() 方法.
		Subject currentUser = SecurityUtils.getSubject();

		// 检测用户是否被认证. 即是否登录.
		if (!currentUser.isAuthenticated()) {
			// 把用户名和密码封装为一个 UsernamePasswordToken 对象.
			UsernamePasswordToken token = new UsernamePasswordToken(username, password);
			token.setRememberMe(true);
			try {
				// 执行登陆操作. 后面进行密码的比对是由 Shiro 完成的.
				System.out.println("-->" + token.hashCode());
				currentUser.login(token);
			}
			// 若用户名不存在, 则会抛出 UnknownAccountException 异常.
			// 可以调用 UsernamePasswordToken 的 token.getPrincipal() 来获取登录信息
			catch (UnknownAccountException uae) {
				System.out.println("用户名不存在: " + uae);
				return "login";
			}
			// 若用户名和密码不匹配, 则会抛出 IncorrectCredentialsException 异常.
			catch (IncorrectCredentialsException ice) {
				System.out.println("用户名和密码不匹配: " + ice);
				return "login";
			}
			// 若该用户被锁定, 则会抛出 LockedAccountException 异常.
			catch (LockedAccountException lae) {
				System.out.println("该用户被锁定: " + lae);
				return "login";
			}
			// 实际上上面所有的异常都是 AuthenticationException 的子类
			catch (AuthenticationException ae) {
				System.out.println("其他的认证异常: " + ae);
				return "login";
			}
		}
		return "success";
	}
	
}
