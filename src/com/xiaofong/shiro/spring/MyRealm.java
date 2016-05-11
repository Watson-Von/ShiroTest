package com.xiaofong.shiro.spring;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthorizingRealm{

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// TODO Auto-generated method stub
		System.out.println("doGetAuthorizationInfo : " + principals);

		// ��ȡ�û��ĵ�¼��Ϣ
		Object principal = principals.getPrimaryPrincipal();

		System.out.println("���� principal: " + principal + " ����ȡ��ǰ�û������е�Ȩ��. ");
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		
		info.addRole("user");
		if ("admin".equals(principal)) {
			info.addRole("admin");
		}
		return info;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		// TODO Auto-generated method stub
		System.out.println("doGetAuthenticationInfo : " + token.hashCode());

		// 1. ����ǿ�Ƶ�����ת��
		UsernamePasswordToken upt = (UsernamePasswordToken) token;

		// 2. ��ȡ�û���
		String username = upt.getUsername();
		if ("uaeUser".equals(username)) {
			throw new UnknownAccountException();
		}
		if ("laeUser".equals(username)) {
			throw new LockedAccountException();
		}

		// 3. �����û��������ݿ��л�ȡ�û���Ϣ
		System.out.println("�����û��� �� " + username + "��ȡ�û���Ϣ��");

		// 4. ���� AuthenticationInfo ʵ��
		// principal : ��¼��Ϣ��Ҳ�����Ƕ�������
		Object principal = username;
		// credentials: ƾ֤. ���� 3 �������ݿ��л�ȡ���û�������
		String credentials = "e5a4dfe682763257640a8a4f62110f68";
		// realmName: ��ǰ Realm �� name. ����ֱ�ӵ��� getName() �������
		String realmName = getName();
		// credentialsSalt: �������ʱ����. Ϊ ByteSource ����
		ByteSource credentialsSalt = ByteSource.Util.bytes("xiaofong");
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, credentials, credentialsSalt, realmName);

		return info;
	}
	
	public static void main(String[] args) {
		String hashAlgorithmName = "MD5";
		String credentials = "123456";
		ByteSource salt = ByteSource.Util.bytes("xiaofong");
		int hashIterations = 1024;

		Object result = new SimpleHash(hashAlgorithmName, credentials, salt, hashIterations);
		System.out.println(result);// 038bdaf98f2037b31f1e75b5b4c9b26e
	}

}
