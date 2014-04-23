import json
import hashlib
import pprint
import random
import requests
import sys
import yaml

ENDPOINT = 'https://api.rememberthemilk.com/services/rest/'

# TODO: namedtuple...
def load_config(path='config.yaml'):
    with open(path, 'r') as f:
        config = yaml.load(f)

    for key in ('api_key', 'shared_secret'):
        if not key in config:
            raise ValueError('Missing "{key}" from config'.format(key=key))

    return config

def get_frob(api_key, shared_secret):
    params = {
        'method': 'rtm.auth.getFrob',
        'api_key': api_key,
        'format': 'json'
    }
    api_sig = calculate_secret(shared_secret, params)
    params['api_sig'] = api_sig
    r = requests.get(
        ENDPOINT,
        params=params,
    )
    response = json.loads(r.text)['rsp']

    if 'frob' not in response or response['stat'] != 'ok':
        raise ValueError('Got an invalid response from frob:\n{response}'.format(response=r.text))
    return response['frob']

def show_authorize_url(api_key, shared_secret):
    """Construct an auth url for a user.

    https://www.rememberthemilk.com/services/api/authentication.rtm
    """
    frob = get_frob(api_key, shared_secret)
    params = {
        'api_key': api_key,
        'perms': 'read',
        'frob': frob,
    }
    api_sig = calculate_secret(shared_secret, params)
    params['api_sig'] = api_sig
    endpoint = 'http://www.rememberthemilk.com/services/auth/'
    r = requests.get(endpoint, params=params)
    print frob, r.url

def get_auth_token(api_key, shared_secret, frob):
    params = {
        'api_key': api_key,
        'frob': frob,
        'method': 'rtm.auth.getToken',
        'format': 'json',
    }
    api_sig = calculate_secret(shared_secret, params)
    params['api_sig'] = api_sig
    r = requests.get(ENDPOINT, params=params)
    response = json.loads(r.text)['rsp']

    pprint.pprint(response)
    auth = response['auth']
    return auth['token']


def main(args=None):
    args = args or sys.argv[1:]

    conf = load_config()
    api_key = conf['api_key']
    shared_secret = conf['shared_secret']

    if args:
        if args[0] == 'frob':
            show_authorize_url(api_key, shared_secret)
        elif args[0] == 'token':
            token = get_auth_token(api_key, shared_secret, conf['frob'])
            print 'Token: "{token}"'.format(token=token)
        return

    # Now assume frob & token are in conf and valid

#    params = {
#        'method': 'rtm.lists.getList',
#        'format': 'json',
#        'api_key': api_key,
#        'auth_token': conf['token']
#    }
    params = {
        'method': 'rtm.tasks.getList',
        'filter': '(list:work due:today)',
        'format': 'json',
        'api_key': api_key,
        'auth_token': conf['token'],
    }
    api_sig = calculate_secret(shared_secret, params)
    params['api_sig'] = api_sig

    r = requests.get(ENDPOINT, params=params)
    response = json.loads(r.text)
#    pprint.pprint(response)

    # XXX: This will crash if there is an error
    list_items = response.get('rsp', {}).get('tasks', {}).get('list', [])[0].get('taskseries', {})
#    pprint.pprint(list_items)
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


def calculate_secret(shared_secret, params_dict):
    sorted_concatendated_params = ''.join(
        sorted(
            "{k}{v}".format(k=k, v=v)
            for k, v in params_dict.iteritems()))

    return hashlib.md5(shared_secret+sorted_concatendated_params).hexdigest()


if __name__ == '__main__':
    main()
