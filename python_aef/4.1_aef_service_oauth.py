from flask import Flask, jsonify, request
from flask_jwt_extended import jwt_required, JWTManager, get_jwt_identity, get_jwt
import ssl
from werkzeug import serving
import socket, ssl
import OpenSSL
from OpenSSL import crypto
import jwt

app = Flask(__name__)

jwt_flask = JWTManager(app)

# hostname='capifcore'
# port=443


# context = ssl.create_default_context()
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# ssl_sock = context.wrap_socket(s, server_hostname=hostname)
# ssl_sock.connect((hostname, port))
# ssl_sock.close()

## problem with get server certificate
#cert = ssl.get_server_certificate((hostname, port))
# print(cert)

with open("cert_server.pem", "rb") as cert_file:
            cert= cert_file.read()

crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
pubKeyObject = crtObj.get_pubkey()
pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM,pubKeyObject)

print ("%s" % pubKeyString)
app.config['JWT_ALGORITHM'] = 'RS256'
app.config['JWT_PUBLIC_KEY'] = pubKeyString


@app.route("/goodbye", methods=["POST"])
@jwt_required()
def goodbye_endpoint():

    #claims = get_jwt()

    name = request.json['name']
    return {"msg": "goodbye " + name}


if __name__ == '__main__':
    serving.run_simple("0.0.0.0", 8087, app)