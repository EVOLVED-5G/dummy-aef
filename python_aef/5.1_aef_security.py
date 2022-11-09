from flask import Flask, jsonify, request
import requests
import json
import ssl

from werkzeug import serving


app = Flask(__name__)

with open('demo_values.json', 'r') as demo_file:
        demo_values = json.load(demo_file)


@app.route("/check-authentication", methods=["POST"])
def check_auth():
    print("He llegado al check sin hacer la verificación")
    invoker_id = request.get_json()
    invoker_id = invoker_id["apiInvokerId"]
    print(invoker_id)
    # supported_feature = request.json['supportedFeatures']


    url = "https://capifcore/capif-security/v1/trustedInvokers/{}".format(invoker_id)
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("GET", url, headers=headers, cert=('APF_dummy.crt', 'APF_private_key.key'), verify="ca.crt")
    response.raise_for_status()
    response_payload = json.loads(response.text)
    print(response_payload)
    for security_context in response_payload["securityInfo"]:
        if security_context["aefId"] == demo_values["aef_id"] and security_context["selSecurityMethod"] == "PKI":
            with open("./certs/myCA.pem", "rb") as ca_file:
                ca_service = ca_file.read()
                my_ca_file = ca_service.decode('utf-8')
            return jsonify(message="Validated User", ca_service=my_ca_file), 201
    return jsonify(message="Not auth user or invalid security method"), 400



@app.route("/revoke-authzorization", methods=["POST"])
def revoke_auth():
    body = request.get_json()
    invoker_id = body["revokeInfo"]["apiInvokerId"]
    api_ids = body["revokeInfo"]["apiIds"]

    #In this section its needed add the acces to resource to remove auth of
    #api invokers using aipInvoker and apiIds
    return 200

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_OPTIONAL
context.check_hostname=False
ssl._create_default_https_context = ssl._create_unverified_context
context.load_verify_locations("ca.crt")
context.load_cert_chain("./certs/server-cert.pem", "./certs/server-key.pem")



if __name__ == '__main__':
   serving.run_simple("0.0.0.0", 8086, app, ssl_context=context)