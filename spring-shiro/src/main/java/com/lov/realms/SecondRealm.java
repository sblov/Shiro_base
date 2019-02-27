package com.lov.realms;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.util.ByteSource;

public class SecondRealm  extends AuthenticatingRealm{

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
//		System.out.println("doGetAuthenticationInfo:"+token);
		System.out.println("SecondRealm");
		
		//1、将AuthenticationToken强转为UsernamePasswordToken
		UsernamePasswordToken upToken = (UsernamePasswordToken)token;
		//2、获取username
		String username =  upToken.getUsername();
		//3、数据库查询
		System.out.println("从数据库获取"+username+"的信息");
		//4、异常检测
		if ("unknown".equals(username)) {
			throw new UnknownAccountException("user not exist");
		}
		if ("master".equals(username)) {
			throw new LockedAccountException("user been locked");
		}
		
		//5、根据用户情况，构建AuthenticationInfo对象并返回，通常使用SimpleAuthenticationInfo
		//认证实体信息
		Object principal = username;
		//密码
		Object credentials = null;
		if (username.equals("user")) {
			credentials = "2bbffae8c52dd2532dfe629cecfb2c85";
		}else if (username.equals("admin")) {
			credentials = "c41d7c66e1b8404545aa3a0ece2006ac";
		} 
		//当前realm对象的name
		String realmName = getName();
		
		SimpleAuthenticationInfo info = null;//new SimpleAuthenticationInfo(principal, credentials, realmName);
		
		ByteSource credentialsSalt = ByteSource.Util.bytes(username);
		info = new SimpleAuthenticationInfo(principal, credentials, credentialsSalt , realmName);
		
		return info;
	}
	



}

