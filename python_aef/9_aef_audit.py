import requests
import json
import configparser
import os
import redis
from termcolor import colored

# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')


def audit_logs_from_capif(capif_ip, ccf_url, query_params):
    print(colored("Audit Logs from CAPIF", "yellow"))

    url = 'https://{}/{}'.format(capif_ip, ccf_url)
    # payload = open('invocation_log.json', 'rb')

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''", "blue"))
        print(colored(f"Request: to {url}", "blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("GET", url, params=query_params, cert=('dummy_amf.crt', 'AMF_private_key.key'), verify='ca.crt')
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print(colored("''''''''''RESPONSE'''''''''''''''''", "green"))
        print(colored(f"Response to: {response.url}", "green"))
        print(colored(f"Response Headers: {response.headers}", "green"))
        print(colored(f"Response: {response.json()}", "green"))
        print(colored(f"Response Status code: {response.status_code}", "green"))
        print(colored("Success, registered api service to CAPIF", "green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''", "green"))
        return response_payload
    except requests.exceptions.HTTPError as err:
        message = json.loads(err.response.text)
        status = err.response.status_code
        raise Exception(message, status)


if __name__ == '__main__':

    capif_ip = os.getenv('CAPIF_HOSTNAME')
    capif_port = os.getenv('CAPIF_PORT')

    api_prov_dom_id = "aec2b52e89a441c6eeabc3369ade6c"  # e.g. ad86d053cb8fcab17fb3d274889b5c
    api_invoker_id = "6ab4944d487247cc2f6b643c168d8d"   # e.g. 105c22ea5f8f983b4ebba594363fcd
    time_start = None       # e.g. 2022-10-24T00:00:00.000Z
    time_end = None         # e.g. 2022-10-25T00:00:00.000Z
    api_id = None           # e.g. f7ba97e8f08a7f53365ba81be60a0c
    api_name = None         # e.g. dummy-aef
    api_version = None      # e.g. v1
    result = None           # e.g. 201
    resource_name = None    # e.g. hello-endpoint
    protocol = None         # e.g. HTTP_1_1 or HTTP_2
    operation = 'GET'        # e.g. POST
    dest_interface = None   # e.g. '{"ipv4_addr": "python-netapp","port": 8087,"security_methods": ["PKI"]}'
    src_interface = None    # e.g. '{"ipv4_addr": "python-aef","port": 8088,"security_methods": ["PKI"]}'

    params = dict()
    if api_prov_dom_id is not None:
        params.update({'aef-id': api_prov_dom_id})

    if api_invoker_id is not None:
        params.update({'api-invoker-id': api_invoker_id})

    if time_start is not None:
        params.update({'time-range-start': time_start})

    if time_end is not None:
        params.update({'time-range-end': time_end})

    if api_id is not None:
        params.update({'api-id': api_id})

    if api_name is not None:
        params.update({'api-name': api_name})

    if api_version is not None:
        params.update({'api-version': api_version})

    if result is not None:
        params.update({'result': result})

    if resource_name is not None:
        params.update({'resource-name': resource_name})

    if protocol is not None:
        params.update({'protocol': protocol})

    if operation is not None:
        params.update({'operation': operation})

    if dest_interface is not None:
        params.update({'dest-interface': dest_interface})

    if src_interface is not None:
        params.update({'src-interface': src_interface})

    print(params)
    ccf_log_url = "logs/v1/apiInvocationLogs"
    log_res = audit_logs_from_capif(capif_ip, ccf_log_url, params)
    print(colored(f"Log response: {log_res}", "yellow"))