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
		// ��ȡ��ǰ�� Subject ʵ��. ͨ�� SecurityUtils.getSubject() ����.
		Subject currentUser = SecurityUtils.getSubject();

		// ����û��Ƿ���֤. ���Ƿ��¼.
		if (!currentUser.isAuthenticated()) {
			// ���û����������װΪһ�� UsernamePasswordToken ����.
			UsernamePasswordToken token = new UsernamePasswordToken(username, password);
			token.setRememberMe(true);
			try {
				// ִ�е�½����. �����������ıȶ����� Shiro ��ɵ�.
				System.out.println("-->" + token.hashCode());
				currentUser.login(token);
			}
			// ���û���������, ����׳� UnknownAccountException �쳣.
			// ���Ե��� UsernamePasswordToken �� token.getPrincipal() ����ȡ��¼��Ϣ
			catch (UnknownAccountException uae) {
				System.out.println("�û���������: " + uae);
				return "login";
			}
			// ���û��������벻ƥ��, ����׳� IncorrectCredentialsException �쳣.
			catch (IncorrectCredentialsException ice) {
				System.out.println("�û��������벻ƥ��: " + ice);
				return "login";
			}
			// �����û�������, ����׳� LockedAccountException �쳣.
			catch (LockedAccountException lae) {
				System.out.println("���û�������: " + lae);
				return "login";
			}
			// ʵ�����������е��쳣���� AuthenticationException ������
			catch (AuthenticationException ae) {
				System.out.println("��������֤�쳣: " + ae);
				return "login";
			}
		}
		return "success";
	}
	
}
