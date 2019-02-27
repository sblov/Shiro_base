<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
    
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
	<h1>list.jsp</h1>	<shiro:principal></shiro:principal>
	<shiro:hasRole name="user">
	<a href="user.jsp">user</a>	
	</shiro:hasRole>
	
	<shiro:hasRole name="admin">
	
	<a href="admin.jsp">admin</a>
	</shiro:hasRole>
	
	<br><br>
	<a href="shiro/testShiroAnnotation">Test ShiroAnnotation</a>
	
	
	<a href="shiro/logout">Logout</a>
</body>
</html>