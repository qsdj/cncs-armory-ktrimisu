# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Cttis_0101' # 平台漏洞编号
    name = '中国铁通江苏分公司WebDAV的远程执行代码' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2011-12-26'  # 漏洞公布时间
    desc = '''
    此漏洞影响/admin
    恶意用户可以在这个系统上执行任意代码。可能危及系统的安全。
    攻击的详细信息
    ASP壳http://www.cttjs.com/admin/acu_test_5Itlt.asp; JPG。
    扫描器会尝试删除这个文件，但它可能没有足够的权限这样做。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=3023
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Cttis'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f71c9b80c-aea4-458d-886f-8fcf138a2930' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/images/yewu/197200/acu_test_jO9Ka.aspjpg"
            url  = self.target + payload
            response = requests.get(url)
            if "This is a test file" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()