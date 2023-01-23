
import requests
import json
import configparser
import os
from termcolor import colored

# Get environment variables


from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import (dump_certificate_request, dump_privatekey, load_publickey, PKey, TYPE_RSA, X509Req, dump_publickey)

def create_csr(name):

        # create public/private key
        key = PKey()
        key.generate_key(TYPE_RSA, 2048)

        # Generate CSR
        req = X509Req()
        req.get_subject().CN = config.get("credentials", "exposer_cn")+name
        req.get_subject().O = 'Telefonica I+D'
        req.get_subject().C = 'ES'
        req.set_pubkey(key)
        req.sign(key, 'sha256')


        csr_request = dump_certificate_request(FILETYPE_PEM, req)

        private_key = dump_privatekey(FILETYPE_PEM, key)

        return csr_request, private_key


def register_exposer_to_capif(capif_ip, capif_port, username, password, role, description, cn):

    print(colored("Registering exposer to CAPIF","yellow"))
    url = "http://{}:{}/register".format(capif_ip, capif_port)

    payload = dict()
    payload['username'] = username
    payload['password'] = password
    payload['role'] = role
    payload['description'] = description
    payload['cn'] = cn

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"Request Body: {json.dumps(payload)}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("Success to register new exposer","green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        return response_payload['id'], response_payload['ccf_publish_url'], response_payload['ccf_api_onboarding_url']
    except requests.exceptions.HTTPError as err:
        raise Exception(err.response.text, err.response.status_code)


def get_capif_auth(capif_ip, capif_port, username, password):

    print("Geting Auth to exposer")
    url = "http://{}:{}/getauth".format(capif_ip, capif_port)

    payload = dict()
    payload['username'] = username
    payload['password'] = password

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print("''''''''''REQUEST'''''''''''''''''")
        print("Request: to ",url) 
        print("Request Headers: ",  headers) 
        print("Request Body: ", json.dumps(payload))
        print("''''''''''REQUEST'''''''''''''''''")

        response = requests.request("POST", url, headers=headers, data=json.dumps(payload))

        response.raise_for_status()
        response_payload = json.loads(response.text)

        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("Get AUTH Success. Received access token", "green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        return response_payload['access_token']
    except requests.exceptions.HTTPError as err:
        raise Exception(err.response.text, err.response.status_code)

def register_api_provider_to_capif(capif_ip, ccf_url, access_token):

    print("Registering api provider to CAPIF")

    url = 'https://{}/{}'.format(capif_ip, ccf_url)
    json_file = open('api_provider_domain.json', "rb")
    payload_dict = json.load(json_file)
    payload_dict["regSec"]=access_token

    for api_func in payload_dict['apiProvFuncs']:
        public_key, private_key = create_csr(api_func["apiProvFuncRole"])
        api_func["regInfo"]["apiProvPubKey"] = public_key.decode("utf-8")
        private_key_file = open(api_func["apiProvFuncRole"]+"_private_key.key", 'wb+')
        private_key_file.write(bytes(private_key))
        private_key_file.close()

    payload = json.dumps(payload_dict)

    headers = {
        'Authorization': 'Bearer {}'.format(access_token),
        'Content-Type': 'application/json'
    }

    try:

        print(colored("''''''''''REQUEST'''''''''''''''''","blue"))
        print(colored(f"Request: to {url}","blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("POST", url, headers=headers, data=payload, verify='ca.crt')
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))
        print(colored(f"Response to: {response.url}","green"))
        print(colored(f"Response Headers: {response.headers}","green"))
        print(colored(f"Response: {response.json()}","green"))
        print(colored(f"Response Status code: {response.status_code}","green"))
        print(colored("Success, registered api provider domain to CAPIF","green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''","green"))

        for func_provile in response_payload["apiProvFuncs"]:
            print(func_provile['regInfo']['apiProvCert'])
            certification_file = open(func_provile["apiProvFuncRole"]+'_dummy.crt', 'wb')
            certification_file.write(bytes(func_provile['regInfo']['apiProvCert'], 'utf-8'))
            certification_file.close()

        return response_payload

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
    capif_ip = os.getenv('CAPIF_HOSTNAME')
    capif_port = os.getenv('CAPIF_PORT')

    if os.path.exists("demo_values.json"):
        os.remove("demo_values.json")

    demo_values = {}

    #First we need register exposer in CAPIF
    try:
        if 'providerID' not in demo_values:
            providerID, ccf_publish_url, ccf_api_onboarding_url = register_exposer_to_capif(capif_ip, capif_port, username, password, role, description,cn)
            demo_values['providerID'] = providerID
            demo_values['ccf_publish_url']= ccf_publish_url
            demo_values['ccf_api_onboarding_url']= ccf_api_onboarding_url
            print("provider ID: {}".format(providerID))
    except Exception as e:
        status_code = e.args[0]
        if status_code == 409:
            print("User already registed. Continue with token request\n")
        else:
            print(e)

    #Second, we need get auth, in this case create cert and private key file
    try:
        if 'capif_access_token_exposer' not in demo_values and 'providerID' in demo_values:
            access_token = get_capif_auth(capif_ip, capif_port, username, password)
            demo_values['capif_access_token_exposer'] = access_token

    except Exception as e:
        status_code = e.args[0]
        if status_code == 401:
            print("Bad credential or User not found\n")
        else:
            print(e)
        capif_access_token = None


    #Third publish service in CAPIF
    try:
        if 'ccf_api_onboarding_url' in demo_values and 'providerID' in demo_values and "capif_access_token_exposer" in demo_values:

            ccf_publish_url = demo_values['ccf_publish_url']
            capif_access_token = demo_values['capif_access_token_exposer']
            ccf_api_onboarding_url = demo_values['ccf_api_onboarding_url']

            response = register_api_provider_to_capif(capif_ip, ccf_api_onboarding_url, capif_access_token)

            for api_prov_func in response["apiProvFuncs"]:
                if api_prov_func["apiProvFuncRole"] == "AEF":
                    demo_values["aef_id"] = api_prov_func["apiProvFuncId"]
                elif api_prov_func["apiProvFuncRole"] == "APF":
                    demo_values["apf_id"] = api_prov_func["apiProvFuncId"]

            api_prov_dom_id = response["apiProvDomId"]
            print(colored(f"API provider domain Id: {api_prov_dom_id}","yellow"))
    except Exception as e:
        status_code = e.args[0]
        if status_code == 401:
            message = e.args[0]
            if str(message).find("Token has expired") != -1:
                capif_access_token = get_capif_auth(capif_ip, capif_port, username, password)
                demo_values['capif_access_token_exposer'] = capif_access_token
                print("New Capif Token: {}".format(capif_access_token))
                print("Run the script again to publish a Service API")
            elif str(message).find("Exposer not existing") != -1:
                print("Exposer not existing. Exposer id not found")
            else:
                print(e)
        elif status_code == 403:
            print("API provider domain already registered.")
        else:
            print(e)

    with open('demo_values.json', 'a') as outfile:
        json.dump(demo_values, outfile)
