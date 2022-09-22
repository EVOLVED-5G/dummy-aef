from flask import Flask, jsonify, request
from flask_jwt_extended import create_access_token, JWTManager
import ssl
from werkzeug import serving


app = Flask(__name__)

jwt = JWTManager(app)

app.config["JWT_SECRET_KEY"] = "this-is-secret-key"

@app.route("/check-authentication", methods=["POST"])
def check_auth():
    #invoker_id = request.json['apiInvokerId']
    # supported_feature = request.json['supportedFeatures']
    access_token = create_access_token(identity=("invoker_authorized"))
    return jsonify(message="Token returned successfully", access_token=access_token), 201



@app.route("/revoke-authzorization", methods=["POST"])
def revoke_auth():
    pass

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname=False
ssl._create_default_https_context = ssl._create_unverified_context
context.load_verify_locations("ca.crt")
context.load_cert_chain("domain.crt", "domain.key")


if __name__ == '__main__':
   serving.run_simple("0.0.0.0", 8085, app, ssl_context=context)