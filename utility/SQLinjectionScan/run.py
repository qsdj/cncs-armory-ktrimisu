# -*- coding: utf-8 -*-
import os
import json
import time
import logging
import requests
import threading
import argparse
from urlparse import urlparse

FORMAT = '%(asctime)-15s %(clientip)s %(user)-8s %(message)s'
logging.basicConfig(format=FORMAT)


class AutoSqli(object):
    """
    使用sqlmapapi的方法进行与sqlmapapi建立的server进行交互
    """

    def __init__(self, server='', target='', data='', referer='', cookie=''):
        self.server = server
        if self.server[-1] != '/':
            self.server = self.server + '/'
        self.target = target
        self.taskid = ''
        self.engineid = ''
        self.status = ''
        self.data = data
        self.referer = referer
        self.cookie = cookie
        self.start_time = time.time()

    def task_new(self):
        self.taskid = json.loads(
            requests.get(self.server + 'task/new').text)['taskid']
        logging.info('Created new task {}'.format(self.taskid))
        if len(self.taskid) > 0:
            return True
        return False

    def task_delete(self):
        del_req_result = requests.get(
            self.server + 'task/' + self.taskid + '/delete').text
        if json.loads(del_req_result)['success']:
            logging.info('Task {} removed'.format(self.taskid))
            return True
        return False

    def scan_start(self):
        headers = {'Content-Type': 'application/json'}
        payload = {'url': self.target}
        url = self.server + 'scan/' + self.taskid + '/start'
        t = json.loads(
            requests.post(url, data=json.dumps(payload), headers=headers).text)
        self.engineid = t['engineid']
        if len(str(self.engineid)) > 0 and t['success']:
            logging.info('Task {} started'.format(self.taskid))
            return True
        return False

    def scan_status(self):
        scan_status_req_result = requests.get(
            self.server + 'scan/' + self.taskid + '/status').text
        self.status = json.loads(scan_status_req_result)['status']
        if self.status == 'running':
            return 'running'
        elif self.status == 'terminated':
            return 'terminated'
        else:
            return 'error'

    def scan_data(self):
        self.data = json.loads(
            requests.get(self.server + 'scan/' + self.taskid + '/data').text
        )['data']
        if len(self.data) == 0:
            return None
        else:
            if isinstance(self.data, (str, unicode)):
                return self.data
            else:
                return json.dumps(self.data)

    def option_set(self):
        headers = {'Content-Type': 'application/json'}
        option = {"options": {"smart": True}}
        url = self.server + 'option/' + self.taskid + '/set'
        requests.post(url, data=json.dumps(option), headers=headers)

    def scan_stop(self):
        requests.get(self.server + 'scan/' + self.taskid + '/stop').text

    def scan_kill(self):
        requests.get(self.server + 'scan/' + self.taskid + '/kill').text

    def run(self):
        if not self.task_new():
            return False
        self.option_set()
        if not self.scan_start():
            return False
        while True:
            if self.scan_status() == 'running':
                time.sleep(10)
            elif self.scan_status() == 'terminated':
                break
            else:
                break
            # timeout 60 * 5 秒
            if time.time() - self.start_time > 300:
                # error = True
                self.scan_stop()
                self.scan_kill()
                break
        scan_result = self.scan_data()
        self.task_delete()
        spend_time = time.time() - self.start_time
        result = {
            'task_id': self.taskid,
            'target': self.target,
            'spend_time': spend_time,
            'positive': scan_result is not None,
        }
        if scan_result is not None:
            result['scan_result'] = scan_result
            result['type'] = 'sql_injection'
        print(json.dumps(result))


def create_cmd_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '--target', required=True, type=str, dest='target',
        help='识别目标主机 URL/IP/域名')
    parser.add_argument(
        '--timeout', required=False, type=int, dest='timeout', default=1800,
        help='爬虫超时时间（单位：秒）默认1800')
    parser.add_argument(
        '--depth-limit', required=False, type=int,
        dest='depth_limit', default=5,
        help='爬虫深度,默认5')
    parser.add_argument(
        '--sqlmapapi', required=True, type=str, dest='sqlmapapi',
        help='sqlmapapi启动后的url; Example:localhost:8000')
    return parser


def AKscan_run(args, runpath=None, json_out_file=None):
    if args.target and runpath:
        # TODO:任务地址
        target = args.target
        parsed = urlparse(target)
        if not parsed.scheme:
            target = 'http://{}'.format(target)

        shell = ("cd {runpath} && python run.py --target {target}"
                 " --json-out-file={json_out_file}").format(
            runpath=runpath, target=target, json_out_file=json_out_file)
    else:
        return
    if args.timeout:
        shell += " --timeout={}".format(args.timeout)
    if args.depth_limit:
        shell += " --depth-limit={}".format(args.depth_limit)
    os.system(shell)


def get_all_urls(filename):
    load_dict = []
    with open(filename, 'r') as load_f:
        try:
            load_dict = json.load(load_f)
        except Exception:
            pass
    for url in load_dict:
        if url["url"]:
            yield url["url"]


def run_sqlmapapi(sqlmapapi, url):
    AutoSqli(sqlmapapi, url).run()


def main():
    BASEDIR = os.path.dirname(os.path.abspath(__file__))
    askscan_path = os.path.join(BASEDIR, "./AKscan/")
    url_jsonPath = os.path.join(BASEDIR, "urls.json")

    if os.path.exists(url_jsonPath):
        os.remove(url_jsonPath)
    parser = create_cmd_parser()
    args = parser.parse_args()
    try:
        # 运行AKscan
        AKscan_run(args, runpath=askscan_path, json_out_file=url_jsonPath)
        sqlmapapi = args.sqlmapapi
        # 线程池最多的装载数量
        runthreadNum = 40
        # 运行sqlmapapi
        threadPool = []
        for url in get_all_urls(url_jsonPath):
            if len(threadPool) >= runthreadNum:
                for t in threadPool:
                    t.start()
                for t in threadPool:
                    t.join()
                threadPool = []
            threadPool.append(threading.Thread(
                target=run_sqlmapapi, args=(sqlmapapi, url)))
        else:
            for t in threadPool:
                t.start()
            for t in threadPool:
                t.join()
    except Exception:
        logging.exeption()


if __name__ == "__main__":
    main()
