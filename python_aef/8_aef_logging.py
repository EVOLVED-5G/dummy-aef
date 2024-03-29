import requests
import json
import configparser
import os
import redis
from termcolor import colored

# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')


def post_log_to_capif(capif_ip, ccf_url):
    print(colored("Post Log to CAPIF", "yellow"))

    url = 'https://{}/{}'.format(capif_ip, ccf_url)
    payload = open('invocation_log.json', 'rb')

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''", "blue"))
        print(colored(f"Request: to {url}", "blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("POST", url, headers=headers, data=payload, cert=('dummy_aef.crt', 'AEF_private_key.key'), verify='ca.crt')
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

    print(colored("''''''''''CAUTION'''''''''''''''''", "yellow"))
    print(colored(f"Edit invocation_log.json file first ...", "yellow"))
    print(colored(f"Fill aefId, apiInvokerId, and apiId with the appropriate values ...", "yellow"))
    print(colored(f"If you have not done it, press \"exit\", else press any key", "yellow"))
    a = input()
    if a == 'exit':
        exit(1)
    print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

    capif_ip = os.getenv('CAPIF_HOSTNAME')
    capif_port = os.getenv('CAPIF_PORT')

    try:
        aef_id = "aec2b52e89a441c6eeabc3369ade6c"
        ccf_log_url = "api-invocation-logs/v1/" + str(aef_id) + "/logs"
        print(colored(f"ccf_log_url: {ccf_log_url}", "yellow"))
        log_res = post_log_to_capif(capif_ip, ccf_log_url)
        print(colored(f"Log response: {log_res}", "yellow"))
    except Exception as e:
        print(e)