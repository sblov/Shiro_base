package com.lov.controller;

import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.lov.service.ShiroService;

@Controller
@RequestMapping("/shiro")
public class ShiroController {

	@Autowired
	private ShiroService shiroService;
	
	@RequestMapping("/testShiroAnnotation")
	public String testShiroAnnotation(HttpSession session){
		session.setAttribute("key", "value12345");
		shiroService.testMethod();
		return "redirect:/list.jsp";
	}
	
	@RequestMapping("/login")
	public String shiroLogin(@RequestParam("username") String username,@RequestParam("password") String password){
		Subject currentUser = SecurityUtils.getSubject();
		
		if (!currentUser.isAuthenticated()) {
			UsernamePasswordToken token = new UsernamePasswordToken(username, password);
			//remenberme
			token.setRememberMe(true);
			
			try {
				currentUser.login(token);
			} catch (AuthenticationException e) {
				System.out.println("login filed:"+e.getMessage());
			}
		}
		
		
		return "redirect:/list.jsp";
	}
	
}
