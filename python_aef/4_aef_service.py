from flask import Flask, jsonify, request
from flask_jwt_extended import jwt_required, JWTManager, get_jwt_identity
import ssl
from werkzeug import serving

app = Flask(__name__)

jwt = JWTManager(app)

app.config["JWT_SECRET_KEY"] = "this-is-secret-key"


@app.route("/hello", methods=["POST"])
@jwt_required()
def check_auth():

    identity = get_jwt_identity()

    if identity != "invoker_authorized":
        return jsonify(message="Not authorized"), 401
    name = request.json['name']
    return {"msg": "hello " + name}


if __name__ == '__main__':
   serving.run_simple("0.0.0.0", 8086, app)