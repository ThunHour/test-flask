from functools import wraps
from os import abort
import enum
from flask import Flask
from flask import jsonify
from flask import request
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity, get_jwt
from flask_jwt_extended import verify_jwt_in_request, jwt_required
from flask_jwt_extended import JWTManager
import datetime
from flask_sqlalchemy import SQLAlchemy
import uuid
import datetime
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import flask_excel as excel


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request(verify_type=True)
            claims = get_jwt()
            if claims["is_administrator"]:
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Admins only!"), 403
        return decorator
    return wrapper


def user_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request(verify_type=True)
            claims = get_jwt()
            if not claims["is_administrator"]:
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="User only!"), 403
        return decorator
    return wrapper


app = Flask(__name__)
CORS(app)
excel.init_excel(app)
# config database
creden='postgresql://kimhour:123@db/flask-project'
app.config['SQLALCHEMY_DATABASE_URI'] = creden
db = SQLAlchemy(app)
app.debug = True

app.config["JWT_SECRET_KEY"] = "hello kon papa"
jwt = JWTManager(app)


# create model
class userRole(enum.Enum):
    USER = 'USER'
    ADMIN = 'ADMIN'

# user model


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.String, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=True)
    role = db.Column(db.String(5), nullable=True)
    reports = db.relationship("Report", backref="user")

    def to_json(self):
        return {
            'id': self.id,
            'username': self.username,
            'password': self.password,
            'role': self.role,
            'email': self.email,
            'reports': [report.report_to_json() for report in self.reports]
        }

# report model


class Report(db.Model):
    __tablename__ = 'report'
    id = db.Column(db.String, primary_key=True)
    date = db.Column(db.Date, nullable=True)
    description = db.Column(db.String(2000), nullable=True)
    session = db.Column(db.Integer, nullable=True)
    isApprove = db.Column(db.Boolean, nullable=True)
    userId = db.Column(db.String(80), db.ForeignKey("user.id"))

    def to_json(self):
        return {
            'id': self.id,
            'date': self.date,
            'description': self.description,
            'session': self.session,
            'isApprove': self.isApprove,
            'userId': self.userId
        }

    def report_to_json(self):
        return {
            'id': self.id,
            'date': self.date,
            'description': self.description,
            'session': self.session,
            'isApprove': self.isApprove,
        }


with app.app_context():
    db.create_all()
    # db.drop_all()


@app.route("/login", methods=["POST"])
def login():
    emailDto = request.json.get("email", None)
    password = request.json.get("password", None)
    credential = User.query.filter_by(email=emailDto).first()
    if emailDto != credential.email or not check_password_hash(credential.password, password):
        return jsonify({"msg": "Bad email or password"}), 401
    if credential.role == "ADMIN":
        access_token = create_access_token(
            identity=credential.id, expires_delta=datetime.timedelta(minutes=10), additional_claims={"is_administrator": True})
    elif credential.role == "USER":
        access_token = create_access_token(
            identity=credential.id, expires_delta=datetime.timedelta(minutes=10), additional_claims={"is_administrator": False})
    return jsonify(token=access_token, role=credential.role, email=credential.email)


@app.route("/register", methods=["POST"])
def register():
    if not request.json:
        abort(400)
    if request.json.get("email") == None:
        return jsonify({"msg": "email is require"}), 400
    if request.json.get("username") == None:
        return jsonify({"msg": "username is require"}), 400
    if request.json.get("password") == None:
        return jsonify({"msg": "password is require"}), 400
    if User.query.filter_by(username=request.json.get("username")).first():
        return jsonify({"msg": "Username already exist!"}), 409
    user = User(id=str(uuid.uuid4()),
                email=request.json.get("email", None),
                username=request.json.get('username', None),
                password=generate_password_hash(
                    request.json.get('password', None)),
                role='USER')
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_json()), 201


@app.route("/user/update", methods=["PUT"])
@user_required()
def updateUser():
    uid = request.args.get("id", None)
    usernameDto = request.json.get("username", None)
    passwordDto = request.json.get("password", None)
    emailDto = request.json.get("email", None)
    if (uid == None):
        return jsonify({"msg": "id is require"}), 400
    if (usernameDto == None):
        return jsonify({"msg": "username is require"}), 400
    if (passwordDto == None):
        return jsonify({"msg": "password is require"}), 400
    if (emailDto == None):
        return jsonify({"msg": "email is require"}), 400
    my_data = User.query.filter_by(id=uid).first()
    my_data.username = usernameDto
    my_data.password = passwordDto
    my_data.email = emailDto
    db.session.commit()
    return jsonify(data=my_data.to_json(), message="Update user successful"), 200



@app.route("/user/delete/<uid>/", methods=["DELETE"])
@admin_required()
def deleteUser(uid):
    if (uid == None):
        return jsonify({"msg": "id is require"}), 400
    user = User.query.filter_by(id=uid).delete()
    if user == 0:
        return jsonify(message="Delete user faild!"), 410
    db.session.commit()
    return jsonify(message="Delete user successful!"), 200


@app.route("/user/getAll", methods=["GET"])
@admin_required()
def getAllUser():
    users = User.query.all()
    return jsonify(data=[user.to_json() for user in users], message="Get all user successful"), 200


@app.route("/report/create", methods=["POST"])
@user_required()
def createReport():
    dateDto = request.json.get("date", None)
    if dateDto == None:
        return jsonify(message="date is require"), 400
    desDto = request.json.get("description", None)
    if desDto == None:
        return jsonify(message="description is require"), 400
    sessionDto = request.json.get("session", None)
    if sessionDto == None:
        return jsonify(message="session is require"), 400
    uId = get_jwt_identity()
    report = Report(id=str(uuid.uuid4()),
                    date=dateDto,
                    description=desDto,
                    session=sessionDto,
                    userId=uId,
                    isApprove=False
                    )
    db.session.add(report)
    db.session.commit()
    return jsonify(report.to_json()), 201


@app.route("/report/update/<rid>", methods=["PUT"])
@user_required()
def updateReprot(rid):
    if rid == None:
        return jsonify(message="id is require"), 400
    dateDto = request.json.get("date", None)
    if dateDto == None:
        return jsonify(message="date is require"), 400
    desDto = request.json.get("description", None)
    if desDto == None:
        return jsonify(message="description is require"), 400
    sessionDto = request.json.get("session", None)
    if sessionDto == None:
        return jsonify(message="session is require"), 400
    userId = request.json.get("userId", None)
    if userId == None:
        return jsonify(message="userId is require"), 400
    userData = Report.query.filter_by(id=rid).first()
    userData.date = dateDto
    userData.description = desDto
    userData.session = sessionDto
    db.session.commit()
    return jsonify(data=userData.to_json(), message="Update report successful"), 200


@app.route("/report/approve/<rid>", methods=["POST"])
@admin_required()
def approveReport(rid):
    report = Report.query.filter_by(id=rid).first()
    report.isApprove = True
    db.session.commit()
    return jsonify(data=report.to_json(), message="Report approved successful"), 200


@app.route("/report/getAll", methods=["GET"])
@admin_required()
def get_report():
    reports = Report.query.all()
    return jsonify([report.to_json() for report in reports])


@app.route("/report/getByUser", methods=["GET"])
@user_required()
def getAllReportByUser():
    uid = get_jwt_identity()
    reports = Report.query.filter_by(userId=uid).all()
    return jsonify([report.to_json() for report in reports])


@app.route("/user/import", methods=["POST"])
def importUser():
    uId = request.form.get("userId", None)
    if uId == None:
        return jsonify(message="user id is require"), 400
    reports = request.get_array(field_name='file')[1:]
    fromCsvToReport = []
    for i in reports:
        fromCsvToReport.append(
            Report(id=str(uuid.uuid4()),date=i[1], description=i[2], session=i[3], isApprove=False, userId=uId))
    db.session.add_all(fromCsvToReport)
    db.session.commit()
    return jsonify({"result": [report.to_json() for report in fromCsvToReport]})


if __name__ == "__main__":
    app.run(port=3000)
