import base64
import datetime
import os
import uuid
import flask
import jwt
from flask import Blueprint, request, url_for, jsonify, make_response, g
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from . import db
from App import UPLOAD_FOLDER, priv_key



ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
bp = Blueprint('api', __name__, url_prefix="/api")
mail = Mail()

global roles
roles = {1: 'Manager', 3: 'User', 2: 'Staff', 4: 'Finance'}


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def conn_curr():
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    return (conn, cur)


@bp.before_app_request
def get_auth_token(user=None):
    auth_header = request.headers.get('Authorization', None)
    if url_for('api.login') == str(request.url_rule):
        pass
    elif auth_header != None:
        try:
            auth_token = auth_header.split(" ")[1]
            resp = decode_token(auth_token)

            conn, cur = conn_curr()
            
            user = cur.execute("SELECT * from user where id=?", (resp,)).fetchone()
            responseObject = user
            g.user = responseObject
        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': str(e)
            }
            return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
                'status': 'fail',
                'message': "Please provide auth token"
            }
        return make_response(jsonify(responseObject)), 401


def encode_token(user_id):
    global cur
    try:

        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=1500),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        token = jwt.encode(payload, priv_key, algorithm='HS256')
        return str(token.decode('utf-8'))
    except Exception as e:
        return e


def decode_token(auth_token):
    try:
        payload = jwt.decode(auth_token, priv_key, algorithms='HS256')
        return payload['sub']

    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError('Signature expired. Please log in again.')

    except jwt.InvalidTokenError:
        raise jwt.ExpiredSignatureError('Invalid token. Please log in again.')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@bp.route('api/email/verify?code=<string:code>')
def email_verify(code=None):
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    json_list = []
    user = cur.execute("SELECT * from user where verification_code=?", (code,)).fetchone()

    conn.execute('UPDATE user set is_verified=?, verification_code where id = ?', (True, 0, user[id],))
    conn.commit()
    user = cur.execute('SELECT * from user where id=?', (id,)).fetchone()
    json_list.append(user)

    return jsonify(json_list)


def forget_password(email, verification):
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    id = uuid.uuid4()
    verification_code = hash(datetime.datetime.now())

    user = cur.execute("SELECT * from user where email=?", (email,)).fetchone()

    conn.execute('INSERT INTO forgotpasswords (id,user_id,email,email_token,created_at) VALUES (?,?,?,?,?)',
                 (id, user['id'], user['email'], verification_code, datetime.datetime.now(),))
    conn.commit()

    msg = Message('Reset your password ',
                  sender='ashketchumreal4life@gmail.com',
                  recipients=[email]
                  )
    msg.body = "Click the Link Below to Verify your Email and Activate your Account \n api/email/verify?code=" + str(
        verification_code) + ".updatewithpassword"
    mail.send(msg)
    print("Sent")


def note_repr(key):
    return {
        'url': request.host_url.rstrip('/') + url_for('notes_detail', key=key)
    }


def send_email(email, verification_code):
    msg = Message('Thank you for registering',
                  sender='ashketchumreal4life@gmail.com',
                  recipients=[email]
                  )
    msg.body = str(verification_code)
    mail.send(msg)
    print("Sent the email")


@bp.route('/genericsearch', methods=['GET', 'POST'])
def search(parameter=None):
    # website = str(request.url).rsplit('/',1)
    #
    # return jsonify(website[1])

    global roles

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(parameter)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allstaff')
def allstaff():
    global roles

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(2)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allmembers')
def allmembers():
    diction = dict(request.headers)

    # return jsonify((diction['Postman-Token']))

    global roles

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(3)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allfinance')
def allfinance():
    global roles

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(4)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allmanagers')
def allmanagers():
    global roles

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(1)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allusers/')
def allUsers():
    global roles

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_users = cur.execute('SELECT * from user').fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users, {})


@bp.route('/terminateduser/')
def terminatedUsers():
    global roles

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_users = cur.execute('SELECT * from user where is_terminated=1').fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users, {})


@bp.route('/updateactivation', methods=['PUT'])
def updateactivation():
    content = flask.request.get_json()

    json_list = []

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()

    id = content['id']

    diction = dict(request.headers)
    try:
        user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                           (diction['Authorization'],)).fetchone()

    except:

        return jsonify("Un Authorized Token")

    conn.execute('UPDATE user set status=? where id=?', (0, id,))
    conn.commit()
    user = cur.execute('SELECT * from user where id=?', (id,)).fetchone()
    json_list.append(user)

    return jsonify(json_list)


@bp.route('/updateterminated', methods=['PUT'])
def updateterminated(id=None):
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()

    diction = dict(request.headers)
    try:
        user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                           (diction['Authorization'],)).fetchone()

    except:

        return jsonify("Un Authorized Token")

    content = flask.request.get_json()

    json_list = []

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()

    id = content['id']

    conn.execute('UPDATE user set is_terminated=? where id=?', (1, id,))

    conn.commit()

    user = cur.execute('SELECT * from user where id=?', (id,)).fetchone()

    json_list.append(user)

    return jsonify(json_list)


@bp.route('/user', methods=['PUT'])
def editProfile():
    if request.method == 'POST':
        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)
        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        diction = dict(request.headers)

        Userkey = diction['Authorization']

        content = flask.request.get_json()

        json_list = []

        name = content['name']

        user_id = content['id']

        phone = content['phone']

        image = str(content['image'])

        image = image.split('base64,')[-1]

        if image != "NULL":
            image = image.encode('utf-8')

            decode_image = base64.decodebytes(image + b'===')

            image = decode_image

            image_id = uuid.uuid4()

            image_path = str(image_id)

            file = open(os.path.join(UPLOAD_FOLDER, (image_path + ".jpeg")), 'wb')
            file.write(image)
            file.close()

            # file.save(os.path.join(UPLOAD_FOLDER, (image_path)))

            user = cur.execute("SELECT * from user where id=?", (id,)).fetchone()

            conn.execute(
                'UPDATE images set id=?, url=?, user_id=?,created_at=?',
                (str(image_id), str(os.path.join(UPLOAD_FOLDER, (image_path + ".jpeg"))), user['id'],
                 datetime.datetime.now())
            )
            conn.commit()

        conn.execute('UPDATE user set name=?,phone=?,  where remember_token=? ',
                     (name, phone, Userkey,))
        conn.commit()

        user = cur.execute('SELECT * from user where remember_token=?', (diction,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)

    else:
        diction = dict(request.headers)
        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        user = cur.execute('SELECT * from user where remember_token=?', (diction,)).fetchone()

        return jsonify(user)


@bp.route('/userId/<int>:key', methods=['PUT'])
def editUser(key):
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()

    diction = dict(request.headers)
    try:
        user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                           (diction['Authorization'],)).fetchone()

    except:

        return jsonify("Un Authorized Token")

    if request.method == 'POST':

        Userkey = key

        content = flask.request.get_json()

        json_list = []

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        name = content['name']
        email = content['email']
        phone = content['phone']
        password = content['password']
        role = content['role_id']

        image = str(content['image'])

        image = image.split('base64,')[-1]

        if image != "NULL":
            image = image.encode('utf-8')

            decode_image = base64.decodebytes(image + b'===')

            image = decode_image

            image_id = uuid.uuid4()

            image_path = str(image_id)

            file = open(os.path.join(UPLOAD_FOLDER, (image_path + ".jpeg")), 'wb')
            file.write(image)
            file.close()

            # file.save(os.path.join(UPLOAD_FOLDER, (image_path)))

            user = cur.execute("SELECT * from user where id=?", (id,)).fetchone()

            conn.execute(
                'UPDATE images set id=?, url=?, user_id=?,created_at=?',
                (str(image_id), str(os.path.join(UPLOAD_FOLDER, (image_path + ".jpeg"))), user['id'],
                 datetime.datetime.now())
            )
            conn.commit()

        pass_check = cur.execute('SELECT * from user where id=?', (Userkey,)).fetchone()

        if email is None or password is None or phone is None:

            json_list.append("The {0} Email, Contact Info and Password are required for update".format(name))

        elif name is None:
            json_list.append("The {0} Name cannot be null ".format(email))

        # elif not check_password_hash(pass_check['password'], password):
        #     json_list.append(str(email) + " of has password Error ")
        else:

            conn.execute('UPDATE user set name=?,phone=?, email = ?, password = ?, role_id=? where id=? ',
                         (name, phone, email, generate_password_hash(password), role, Userkey,))
            conn.commit()
            user = cur.execute('SELECT * from user where id=?', (Userkey,)).fetchone()
            json_list.append(user)

        return jsonify(json_list)
    else:
        Userkey = key
        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()
        user = cur.execute('SELECT * from user where id=?', (Userkey,)).fetchone()

        return jsonify(user)


@bp.route('/deleteuser', methods=['DELETE'])
def deletex():
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()

    diction = dict(request.headers)
    try:
        user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                           (diction['Authorization'],)).fetchone()

    except:

        return jsonify("Un Authorized Token")

    content = flask.request.get_json()

    json_list = []

    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()

    email = content['email']

    user_id = content['id']

    try:
        conn.execute('DELETE FROM user where email=?', (email,))
        conn.commit()
    except:
        conn.execute('DELETE FROM user where id=?', (user_id,))
        conn.commit()

    json_list.append('The user has been deleted with the email {0}'.format(email))

    return jsonify(json_list)


@bp.route('/register', methods=['POST'])
def register():
    if request.method == "POST" and g.user['role_id'] == 1:
        conn, cur = conn_curr()

        content = flask.request.get_json()
        
        name = content['name']
        email = content['email']
        password = content['password']
        contact = request.json.get('phone', None)
        role = content['role_id']
        id = uuid.uuid4()
        
        verification_code = hash(datetime.datetime.now())
        created_at = datetime.datetime.now()

        if name is None and email is None and password is None and contact is None:
            return jsonify("Email or password cannot be null")

        elif cur.execute('SELECT id from user where  email=?', (email,)).fetchone() is not None:
            return jsonify("Id already exists")
        else:

            conn.execute(
                'INSERT INTO user(id,name,email,phone,password, role_id, created_at, verification_code, status, '
                'is_verified) '
                'VALUES (?,?,?,?,?,?,?,?,?,?)',
                (str(id), name, email, contact, generate_password_hash(password), role, created_at, verification_code,
                 True, True,))
            conn.commit()

            image = str(content['image'])
            image = image.split('base64,')[-1]
            if image != "NULL":
                image = image.encode('utf-8')
                decode_image = base64.decodebytes(image + b'===')
                image = decode_image
                image_id = uuid.uuid4()
                image_path = str(image_id)

                file = open(os.path.join(UPLOAD_FOLDER, (image_path + ".jpeg")), 'wb')
                file.write(image)
                file.close()

                # file.save(os.path.join(UPLOAD_FOLDER, (image_path)))

                user = cur.execute("SELECT * from user where email=?", (email,)).fetchone()

                conn.execute(
                    'INSERT INTO images (id, url, user_id,created_at)'
                    ' VALUES (?, ?, ?, ?)',
                    (str(image_id), str(os.path.join(UPLOAD_FOLDER, (image_path + ".jpeg"))), user['id'],
                     datetime.datetime.now())
                )
                conn.commit()

            send_email(email, verification_code)
            user = cur.execute("SELECT * from user where email=?", (email,)).fetchone()
            image = cur.execute("SELECT * from images where id=?", (str(image_id),)).fetchone()

            return jsonify(user, image)


@bp.route('/login', methods=['POST'])
def login():
    if request.method == "POST":
        content = flask.request.get_json()
        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        email = content['email']
        password = content['password']

        if email is None or password is None or id is None:
            return jsonify("Email or password cannot be null")

        else:
            pass_check = cur.execute('SELECT * from user where user.email=?', (email,)).fetchone()
            if not check_password_hash(pass_check['password'], password):
                return jsonify("Password Incorrect")
            elif pass_check['is_verified'] != 1:
                return jsonify('Please verify your email address')
            else:
                user = cur.execute("SELECT * from user WHERE email=?",
                                   (email,)).fetchone()
                token = encode_token(user['id'])
                user.pop("password")
                data = {"user": user, "token":token, "success": True,}
                return jsonify(data)


@bp.route('/logout')
def logout():
    responseObject = {
        'status': 'success',
        'message': 'Successfully logged out.'
    }
    return make_response(jsonify(responseObject)), 200


@bp.route('/new-requests', methods=['POST'])
def create_request():
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    content = flask.request.get_json()
    user_id = str(content['id'])
    request_id = str(uuid.uuid4())
    items_array = content['items']
    content = items_array

    for i in range(len(items_array)):

        content_items = content[int(i)]
        # return jsonify(content_items['name'])
        name = content_items['name']
        description = content_items['description']
        quantity = content_items['quantity']
        # price = content[i]['price']

        print("Error")

        user = cur.execute("SELECT * from user WHERE id=?",
                           (user_id,)).fetchone()
        if user['role_id'] == 3:

            status = 'Pending'

        else:

            status = 'Processing'

        conn.execute(
            'INSERT INTO request(_id,user_id,created_at,status,order_created) '
            'VALUES (?,?,?,?,?)',
            (str(request_id), user_id, datetime.datetime.now(), status, True,))
        conn.commit()

        items_id = uuid.uuid4()

        request = cur.execute("SELECT * from request WHERE _id=?",
                              (request_id,)).fetchone()

        conn.execute(
            'INSERT INTO items(id,name,description,price,request_id,created_at,quantity) '
            'VALUES (?,?,?,?,?,?,?)',
            (str(items_id), name, str(description), "0", request['_id'], datetime.datetime.now(), quantity,))
        conn.commit()

        request = cur.execute("SELECT * from request WHERE _id=?",
                              (request['_id'],)).fetchone()
        return jsonify(request)


@bp.route('/process-requests/request-details?requestId=<int:id>', methods=['POST', 'GET'])
def assign_request():
    if request.method == 'POST':

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        staff_id = content['staff_id']

        request_id = content['id']

        user_id = content['user_id']

        json_list = []

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        conn.execute('UPDATE request set staff_id=?, status=? where id=?', (staff_id, 'Processing', request_id,))
        conn.commit()
        user = cur.execute('SELECT * from items where request_id=?', (request_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)

    else:

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        request_id = content['id']

        items = cur.execute('SELECT * from items where request_id=?', (request_id,)).fetchone()

        return jsonify(items)


@bp.route('/new-requests/request-details?requestId=<int:id>', methods=['POST', 'GET'])
def read_request(id=None):
    if request.method == 'POST':

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        request_id = content['id']

        json_list = []

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        user = cur.execute('SELECT * from items, request where request_id=? and request.status="Pending"',
                           (request_id,)).fetchone()

        json_list.append(user)

        return jsonify(json_list)

    else:

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        items = cur.execute('SELECT * from items,request where items.request_id=request._id and '
                            'request.status="Pending" or request.status="Quotes Added" ').fetchall()
        return jsonify(items)


@bp.route('/approved-requests/request-details?requestId=<int:id>', methods=['POST'])
@bp.route('/approved-requests',defaults={'id': None}, methods=['GET'])
def approved_request(id=None):
    if request.method == 'POST':

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        request_id = content['id']

        json_list = []

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        user = cur.execute('SELECT * from items, request where request_id=? and request.status="Approved"',
                           (request_id,)).fetchone()

        json_list.append(user)

        return jsonify(json_list)

    else:

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        items = cur.execute('SELECT * from items,request where items.request_id=request._id and '
                            'request.status="Approved"').fetchall()
        return jsonify(items)


@bp.route('/createquotes/<string:request_id>', methods=['POST'])
def create_quote(request_id=None):
    if request.method == "POST":

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()
        diction = dict(request.headers)
        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=2 ",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        if 'file' not in request.files:
            return jsonify('No Quote has been added')

        files = request.files.getlist("files")

        content = flask.request.get_json()

        # request_id = content['request_id']

        for file in files:
            if file and allowed_file(file.filename):
                file.save(os.path.join(UPLOAD_FOLDER, secure_filename(file.filename)))

                conn.execute(
                    'INSERT INTO quotes (id, path, request_id,status,created_at)'
                    ' VALUES (?, ?, ?, ?,?)',
                    (str(uuid.uuid4()), os.path.join(UPLOAD_FOLDER, secure_filename(file.filename)), request_id,
                     "Quotes "
                     "Added",
                     datetime.datetime.now())
                )
                conn.commit()

        return jsonify("Quote has been added")


@bp.route('/allquotes', methods=['GET'])
def all_quotes():
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()

    diction = dict(request.headers)

    json_list = []

    try:
        user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                           (diction['Authorization'],)).fetchone()

    except:

        return jsonify("Un Authorized Token")

    user = cur.execute('SELECT * from quotes where status<>"Approved"').fetchall()
    json_list.append(user)

    return jsonify(json_list)


# @bp.route('/allquotesverified', methods=['GET'])
# def all_quotes_verified():
#     conn = db.get_db()
#     conn.row_factory = dict_factory
#     cur = conn.cursor()

#     diction = dict(request.headers)

#     json_list = []

#     try:
#         user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
#                            (diction['Authorization'],)).fetchone()

#     except:

#         return jsonify("Un Authorized Token")

#     user = cur.execute('SELECT * from quotes where status="Quotes Added"').fetchall()
#     json_list.append(user)

#     return jsonify(json_list)


@bp.route('orders/order-details?orderId=<int:id>', methods=['POST', 'GET'])
@bp.route('/orders', defaults={'id': None}, methods=['GET'])
def all_quotes_verified(id=None):
    if id is None:
        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        json_list = []

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        user = cur.execute('SELECT * from orders').fetchall()
        json_list.append(user)

        return jsonify(json_list)

    else:

        if request.method == 'GET':

            conn = db.get_db()
            conn.row_factory = dict_factory
            cur = conn.cursor()

            diction = dict(request.headers)

            content = flask.request.get_json()

            order_id = content['order_id']

            comment = content['comment']

            json_list = []

            try:
                user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                                   (diction['Authorization'],)).fetchone()

            except:

                return jsonify("Un Authorized Token")

            conn.execute('UPDATE orders is_sign=?, comment=?  where id=?', (True, comment, order_id,))
            conn.commit()
            user = cur.execute('SELECT * from orders where id=?', (order_id,)).fetchone()
            json_list.append(user)

            return jsonify(json_list)


        else:
            conn = db.get_db()
            conn.row_factory = dict_factory
            cur = conn.cursor()

            diction = dict(request.headers)

            json_list = []

            try:
                user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                                   (diction['Authorization'],)).fetchone()

            except:

                return jsonify("Un Authorized Token")

            user = cur.execute('SELECT * from orders where id=?', (id)).fetchone()
            json_list.append(user)

            return jsonify(json_list)


@bp.route('/approvequote', methods=['POST', 'GET'])
def approve_quote():
    if request.method == 'POST':

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        request_id = content['id']

        user_id = content['user_id']

        json_list = []

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        conn.execute('UPDATE quotes status=? where request_id=?', ('Approved', request_id,))
        conn.commit()
        user = cur.execute('SELECT * from quotes where request_id=?', (request_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)

    else:

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        request_id = content['id']

        items = cur.execute('SELECT * from quotes where request_id=?', (request_id,)).fetchone()

        return jsonify(items)


@bp.route('/createordersfromstaff', methods=['POST'])
def create_orders_from_staff():
    if request.method == "POST":

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()
        diction = dict(request.headers)
        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=3 ",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        if 'file' not in request.files:
            return jsonify('No Quote has been added')

        files = request.files.getlist("files")
        content = request.form

        items_array = content['items']

        request_id = content['request_id']

        total = content['total']

        # for i in range(len(items_array)):
        #     items_array = content[int(i)]
        #
        #     name = items_array['name']
        #
        #     quantity = items_array['quantity']
        #
        #     price = items_array[i]['price']

        ### If No request Id then is_cash is 0
        is_cash = False

        for file in files:
            if file and allowed_file(file.filename):
                file.save(os.path.join(UPLOAD_FOLDER, secure_filename(file.filename)))
                #
                # items_id = str(uuid.uuid4())
                #
                # # description = cur.execute("SELECT items.description from items,request where request.request_id=?",
                # # (str(request_id),))
                # #
                # # conn.execute(
                # #     'INSERT INTO items(id,name,description,price,request_id,created_at,quantity) '
                # #     'VALUES (?,?,?,?,?,?,?)',
                # #     (str(items_id), name, description, price, str(request_id), datetime.datetime.now(), quantity,))
                # # conn.commit()
                #
                # # items = cur.execute('SELECT * from items where id=?', (items_id,)).fetchone()

                conn.execute(
                    'INSERT INTO orders (id, items,request_id, total, staff_id, is_sign ,path,created_at, is_cash, '
                    'is_read, '
                    'comment) '
                    ' VALUES (?, ?, ?, ?,?,?,?,?,?,?,?)',
                    (str(uuid.uuid4()), str(items_array), request_id, total, user['id'], False,
                     os.path.join(UPLOAD_FOLDER, secure_filename(file.filename)), datetime.datetime.now(),
                     is_cash, False)
                )
                conn.commit()

        return jsonify("Order has been added")


@bp.route('/createpurchaseorder', methods=['POST'])
def create_purchase_order():
    if request.method == "POST":

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()
        diction = dict(request.headers)
        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=3 ",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        if 'file' not in request.files:
            return jsonify('No Quote has been added')

        files = request.files.getlist("files")
        content = request.form

        items_array = content['items']

        # request_id = content['request_id']

        total = content['total']

        ### If No request Id then is_cash is 0
        is_cash = True

        for file in files:
            if file and allowed_file(file.filename):
                file.save(os.path.join(UPLOAD_FOLDER, secure_filename(file.filename)))

                conn.execute(
                    'INSERT INTO orders (id, items, total, staff_id, is_sign ,path,created_at, is_cash, is_read, '
                    'comment) '
                    ' VALUES (?, ?, ?, ?,?,?,?,?,?,?)',
                    (str(uuid.uuid4()), str(items_array), total, user['id'], False,
                     os.path.join(UPLOAD_FOLDER + "/Orders", secure_filename(file.filename)), datetime.datetime.now(),
                     is_cash, False)
                )
                conn.commit()

        return jsonify("Purchase Order has been added")


@bp.route('/approveorderfromstaff/<string:order_id>', methods=['POST', 'GET'])
def approve_orderfinance(order_id=None):
    if request.method == 'POST':

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        is_read = content['is_read']

        order_id = order_id

        json_list = []

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=4",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        conn.execute('UPDATE orders is_read=? where id=? and is_sign=True ', (is_read, order_id,))
        conn.commit()
        user = cur.execute('SELECT * from orders where id=?', (order_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)

    else:

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=4",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        order_id = content['id']

        orders = cur.execute('SELECT * from orders where is_sign=True').fetchall()

        return jsonify(orders)


#
#
# @bp.route('/purchaseorder', methods=['POST', 'GET'])
# def approve_purchaseorder():
#     if request.method == 'POST':
#
#         conn = db.get_db()
#         conn.row_factory = dict_factory
#         cur = conn.cursor()
#
#         diction = dict(request.headers)
#
#         content = flask.request.get_json()
#
#         is_read = content['is_read']
#
#         order_id = content['id']
#
#         user_id = content['user_id']
#
#         request_id = content['request_id']
#
#         json_list = []
#
#         try:
#             user = cur.execute("SELECT * from user where remember_token=? and role_id = 4",
#                                (diction['Authorization'],)).fetchone()
#
#         except:
#
#             return jsonify("Un Authorized Token")
#
#         conn.execute('UPDATE orders is_read=? where id=? and is_sign=True and request_id=?',
#                      (is_read, order_id, request_id,))
#         conn.commit()
#         user = cur.execute('SELECT * from orders where id=?', (order_id,)).fetchone()
#         json_list.append(user)
#
#         return jsonify(json_list)
#
#     else:
#
#         conn = db.get_db()
#         conn.row_factory = dict_factory
#         cur = conn.cursor()
#
#         diction = dict(request.headers)
#
#         content = flask.request.get_json()
#
#         try:
#             user = cur.execute("SELECT * from user where remember_token=? and role_id = 4",
#                                (diction['Authorization'],)).fetchone()
#
#         except:
#
#             return jsonify("Un Authorized Token")
#
#         order_id = content['id']
#
#         orders = cur.execute('SELECT * from orders where id=? and is_sign=False ', (order_id,)).fetchone()
#
#         return jsonify(orders)


@bp.route('/approveorderfrommanager', methods=['POST', 'GET'])
def approve_ordermanager():
    if request.method == 'POST':

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        order_id = content['order_id']

        comment = content['comment']

        json_list = []

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        conn.execute('UPDATE orders is_sign=?, comment=?  where id=?', (True, comment, order_id,))
        conn.commit()
        user = cur.execute('SELECT * from orders where id=?', (order_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)

    else:

        conn = db.get_db()
        conn.row_factory = dict_factory
        cur = conn.cursor()

        diction = dict(request.headers)

        content = flask.request.get_json()

        try:
            user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                               (diction['Authorization'],)).fetchone()

        except:

            return jsonify("Un Authorized Token")

        order_id = content['id']

        orders = cur.execute('SELECT * from orders where is_sign=False ').fetchall()

        return jsonify(orders)


@bp.route('/dashboard', methods=['GET'])
def dashboard():
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    diction = dict(request.headers)
    try:
        user = cur.execute("SELECT * from user where remember_token=? and role_id=1",
                           (diction['Authorization'],)).fetchone()

    except:

        return jsonify("Un Authorized Token")

    total_request = cur.execute('SELECT * from request').fetchall()

    count_total_request = cur.execute('SELECT COUNT(*) from request').fetchall()

    # return (count_total_request[0])

    new_request = cur.execute('SELECT * from request where request.status="Pending"').fetchall()

    count_new_request = cur.execute('SELECT COUNT(*) from request where request.status="Pending"').fetchall()

    processing_request = cur.execute('SELECT * from request where request.status="Processing"').fetchall()

    count_processing_request = cur.execute('SELECT COUNT(*) from request where request.status="Processing"').fetchall()

    return jsonify(total_request, new_request, processing_request,
                   {'totalRequests': count_total_request[0], 'pending': count_new_request[0],
                    'waitingForApproval': count_processing_request[0]})
