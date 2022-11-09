import requests
import json
import configparser
import os
from termcolor import colored

def publish_service_api_to_capif(capif_ip, apf_id, aef_id):

    print("Publishing api service to CAPIF")

    url = 'https://{}/published-apis/v1/{}/service-apis'.format(capif_ip, apf_id)
    payload = open('service_api_description_hello.json', 'rb')
    payload_dict = json.load(payload)
    for profile in payload_dict["aefProfiles"]:
        profile["aefId"] = aef_id

    payload_2 = open('service_api_description_goodbye.json', 'rb')
    payload_dict_2 = json.load(payload_2)
    for profile in payload_dict_2["aefProfiles"]:
        profile["aefId"] = aef_id

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("POST", url, headers=headers, data=json.dumps(payload_dict), cert=('APF_dummy.crt', 'APF_private_key.key'), verify='ca.crt')
        response.raise_for_status()
        response_payload = json.loads(response.text)

        response = requests.request("POST", url, headers=headers, data=json.dumps(payload_dict_2), cert=('APF_dummy.crt', 'APF_private_key.key'), verify='ca.crt')
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("Success, registered api service to CAPIF","green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        return response_payload['apiId']
    except requests.exceptions.HTTPError as err:
        message = json.loads(err.response.text)
        status = err.response.status_code
        raise Exception(message, status)

if __name__ == '__main__':

    config = configparser.ConfigParser()
    config.read('credentials.properties')

    username = config.get("credentials", "exposer_username")
    password = config.get("credentials", "exposer_password")
    role = config.get("credentials", "exposer_role")
    description = config.get("credentials", "exposer_description")
    cn = config.get("credentials", "exposer_cn")
    
    # capif_ip = config.get("credentials", "capif_ip")
    # capif_port = config.get("credentials", "capif_port")

    with open('demo_values.json', 'r') as demo_file:
        demo_values = json.load(demo_file)

    capif_ip = os.getenv('CAPIF_HOSTNAME')
    capif_port = os.getenv('CAPIF_PORT')

    #Publish service in CAPIF
    try:
        if 'apf_id' in demo_values:

            ccf_publish_url = demo_values["ccf_publish_url"]
            capif_access_token = demo_values['capif_access_token_exposer']
            service_api_id = publish_service_api_to_capif(capif_ip, demo_values['apf_id'], demo_values['aef_id'])
            if 'services_num' not in demo_values:
                services_num = 0
            else:
                services_num = int(demo_values['services_num'])

            services_num += 1
            demo_values['services_num']= services_num
            demo_values['serviceapiid'+str(services_num)]= service_api_id
            print("Service Api Id: {}".format(service_api_id))
    except Exception as e:
        print(e)

    with open('demo_values.json', 'w') as outfile:
        json.dump(demo_values, outfile)