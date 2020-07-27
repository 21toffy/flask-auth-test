from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash 
import datetime
import jwt
from functools import wraps


#init
app = Flask(__name__)


app.config['SECRET_KEY'] = 'thisissecretkey'
basedir = os.path.abspath(os.path.dirname(__file__))

#Databse
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, "db.sqlite") + 'bucketlist.db'



db = SQLAlchemy(app)

# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#init db


#user Class/model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    # bucketlists = db.relationship('Bucketlist', order_by='Bucketlist.id', cascade="all, delete-orphan", backref='user')



#bucket list Class/Model
class Bucketlist(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    checklist = db.Column(db.String(500))
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer)
    


    def __init__(self,name,checklist, user_id):
        self.name=name
        self.checklist=checklist
        self.user_id = user_id



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message':'Token is missing!'}), 401
        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated







#routes and view/logic enabling an admin and only an admin to view all users
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message':'Can not perform function !'})
    users=User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users':output})



#routes and view/logic enabling an admin and only an admin to view one user
@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_users(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'Can not perform function !'})

    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found'})
    user_data={}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify({'user':user_data})



#routes and view/logic enabling an admin and only an admin to create a user
@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message':'Can not perform function !'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user =User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message':'New user'})




#routes and view/logic enabling an admin and only an admin to edit a users details
@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message':'Can not perform function !'})

    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found'})
    user.admin=True
    db.session.commit()

    return jsonify({'message':'User has been promoted'})




#routes and view/logic enabling an admin and only an admin to delete  users

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message':'Can not perform function !'})

    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message':'No user found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message':'User has been deleted'})



#login route 
@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify',401, {'WWW=Authenticate':'Basic realm="Logi reuired"'})
    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('could not verify',401, {'WWW=Authenticate':'Basic realm="Logi reuired"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id':user.public_id, 'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token':token.decode('UTF-*')})

    return make_response('could not verify',401, {'WWW=Authenticate':'Basic realm="Logi reuired"'})




@app.route('/bucket-list', methods=['GET'])
@token_required
def get_all_bucketlist(current_user):
    bucketlists = Bucketlist.query.filter_by(user_id=current_user.id).all()
    print(current_user.id)

    output=[]
    for bucketlist in bucketlists:
        bucketlist_data = {}
        bucketlist_data['id'] = bucketlist.id
        bucketlist_data['name']= bucketlist.name
        bucketlist_data['checklist']=bucketlist.checklist
        bucketlist_data['date_created']=bucketlist.date_created
        # bucketlist_data['user_id']:bucketlist.user_id
        output.append(bucketlist_data)

    return jsonify({'bucket lists':output})



@app.route('/bucket-list/<bucketlist_id>', methods=['GET'])
@token_required
def get_one_bucketlist(current_user, bucketlist_id):
    bucketlist = Bucketlist.query.filter_by(id=bucketlist_id, user_id=current_user.id).first()
    if not bucketlist:
        return jsonify({'msg':'no bucket list found!!'})
    bucketlist_data = {}
    bucketlist_data['id'] = bucketlist.id
    bucketlist_data['name']= bucketlist.name
    bucketlist_data['date_created']=bucketlist.date_created
    bucketlist_data['checklist']=bucketlist.checklist


    return jsonify(bucketlist_data)


@app.route('/bucket-list', methods=['POST'])
@token_required
def create_bucketlist(current_user):
    data = request.get_json()
    new_bucketlist= Bucketlist(name=data['name'], checklist=data['checklist'], user_id=current_user.id)
    db.session.add(new_bucketlist)
    db.session.commit()
    return jsonify({'msg':'bucket list created!'})


# @app.route('/bucket-list/<bucketlist_id>', methods=['PUT'])
# @token_required
# def comolete_bucketlist(current_user):
#     bucketlist = Bucketlist.query.filter_by(id=bucketlist_id, user_id=current_user.id).first()
#     if not bucketlist:
#         return jsonify({'msg':'no bucket list found!!'})
#     return ''


@app.route('/bucket-list/<bucketlist_id>', methods=['DELETE'])
@token_required
def delete_bucketlist(current_user, bucketlist_id):
    bucketlist = Bucketlist.query.filter_by(id=bucketlist_id, user_id=current_user.id).first()
    if not bucketlist:
        return jsonify({'msg':'no bucket list found!!'})
    db.session.delete(bucketlist)
    db.session.commit()
    
    return jsonify({'msg':'it seems like you have checked one off the list good job'})





#runserver
if __name__ == '__main__':
    app.run(debug=True)


