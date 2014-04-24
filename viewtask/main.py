import json
import pprint
import random
import requests
import sys
import yaml

from viewtask import auth
from viewtask import util


class RememberAPI(object):
    def __init__(self, api_key, shared_secret, token=None, endpoint=util.ENDPOINT, response_format='json'):
        self.api_key = api_key
        self.shared_secret = shared_secret
        self.token = token
        self.endpoint = endpoint
        self.response_format = response_format

    def request(self, method, **kwargs):
        params = {
            'method': method,
            'api_key': self.api_key,
            'format': self.response_format,
        }
        if self.token:
            params['token'] = token
        params.update(kwargs)
        api_sig = util.signature(params)
        params['api_sig'] = api_sig

        r = requests.get(self.endpoint, params=params)
        response = json.loads(r.text)


# TODO: namedtuple...
def load_config(path='config.yaml'):
    with open(path, 'r') as f:
        config = yaml.load(f)

    for key in ('api_key', 'shared_secret'):
        if not key in config:
            raise ValueError('Missing "{key}" from config'.format(key=key))

    return config


def main(args=None):
    args = args or sys.argv[1:]

    conf = load_config()
    api_key = conf['api_key']
    shared_secret = conf['shared_secret']

    if args:
        if args[0] == 'frob':
            auth.show_authorize_url(api_key, shared_secret)
        elif args[0] == 'token':
            token = auth.get_auth_token(api_key, shared_secret, conf['frob'])
            print 'Token: "{token}"'.format(token=token)
        return

    # Now assume frob & token are in conf and valid

    # params = { 'method': 'rtm.lists.getList', 'format': 'json', 'api_key': api_key, 'auth_token': conf['token'] }
    params = {
        'method': 'rtm.tasks.getList',
        'filter': '(list:work due:today)',
        'format': 'json',
        'api_key': api_key,
        'auth_token': conf['token'],
    }
    api_sig = util.signature(shared_secret, params)
    params['api_sig'] = api_sig

    r = requests.get(util.ENDPOINT, params=params)
    response = json.loads(r.text)
    # pprint.pprint(response)

    # XXX: This will crash if there is an error
    list_items = response.get('rsp', {}).get('tasks', {}).get('list', [])[0].get('taskseries', {})
    # pprint.pprint(list_items)
    task = random.choice(list_items)
    pprint.pprint(task)
    present_task(task)

def present_task(task):
    description = task.get('name', '')
    priority = task.get('task', {}).get('priority', 'N')
    priority = int(priority if priority != 'N' else 4)

    print '!{priority}: {description}'.format(
        priority=priority,
        description=description)


if __name__ == '__main__':
    main()
