import json
import hashlib
import pprint
import requests
import sys
import yaml

ENDPOINT = 'https://api.rememberthemilk.com/services/rest/'
temp_frob = '91cf2ab2b0ff534a54c935225a8d5a0a6de826b1'

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

def auth(api_key, shared_secret):
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

def get_auth_token(api_key, shared_secret):
    params = {
        'api_key': api_key,
        'frob': temp_frob,
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

#    r = requests.get(ENDPOINT, params={
#        'method': 'rtm.test.echo',
#        'api_key': api_key,
#        'format': 'json',
#        'foo': 'bar',
#        }
#    )

#    print r.url
#    print r.text
#    pprint.pprint(json.loads(r.text))

#    auth(api_key, shared_secret)
#    return

    token = get_auth_token(api_key, shared_secret)

    params = {
        'method': 'rtm.lists.getList',
        'format': 'json',
        'api_key': api_key,
        'auth_token': token
    }
    api_sig = calculate_secret(shared_secret, params)
    params['api_sig'] = api_sig

    r = requests.get(ENDPOINT, params=params)
    pprint.pprint(json.loads(r.text))


def calculate_secret(shared_secret, params_dict):
    sorted_concatendated_params = ''.join(
        sorted(
            "{k}{v}".format(k=k, v=v)
            for k, v in params_dict.iteritems()))

    return hashlib.md5(shared_secret+sorted_concatendated_params).hexdigest()


if __name__ == '__main__':
    main()
