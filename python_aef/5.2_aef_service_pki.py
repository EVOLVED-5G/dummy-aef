from flask import Flask, jsonify, request
from flask_jwt_extended import jwt_required, JWTManager, get_jwt_identity
import ssl
from werkzeug import serving

app = Flask(__name__)


@app.route("/hello", methods=["POST"])
def hello_endpoint():

    name = request.json['name']
    return {"msg": "hello " + name}


context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname=False
context.load_verify_locations("ca.crt")
context.load_cert_chain("./certs/server-cert.pem", "./certs/server-key.pem")


if __name__ == '__main__':
   serving.run_simple("0.0.0.0", 8088, app, ssl_context=context)