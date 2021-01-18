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

from App import UPLOAD_FOLDER, priv_key
from . import db

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
bp = Blueprint('api', __name__, url_prefix="/api")
mail = Mail()

global roles
roles = {1: 'Manager', 2: 'Staff', 3: 'User',  4: 'Finance'}


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def conn_curr():
    conn = db.get_db()
    conn.row_factory = dict_factory
    cur = conn.cursor()
    return conn, cur


@bp.before_app_request
def get_auth_token(user=None):
    auth_header = request.headers.get('Authorization', None)
    if url_for('api.login') == str(request.url_rule):
        pass
    elif auth_header is not None:
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
    conn, cur = conn_curr()
    json_list = []
    user = cur.execute("SELECT * from user where verification_code=?", (code,)).fetchone()

    conn.execute('UPDATE user set is_verified=?, verification_code where id = ?', (True, 0, user[id],))
    conn.commit()
    user = cur.execute('SELECT * from user where id=?', (id,)).fetchone()
    json_list.append(user)

    return jsonify(json_list)


def forget_password(email, verification):
    conn, cur = conn_curr()
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


@bp.route('/changePassword', methods=['POST'])
def change_password():
    content = flask.request.get_json()
    json_list = []
    conn, cur = conn_curr()
    oldPassword = content['oldPassword']
    password = content['password']

    if check_password_hash(g.user['password'], oldPassword):
        conn.execute('UPDATE user set password=? where user.id=?', (generate_password_hash(password) ,g.user['id'],))
        conn.commit()
        user = cur.execute('SELECT * from user where id=?', (g.user['id'],)).fetchone()
        json_list.append(user)
        return jsonify(json_list)
    else:
        return jsonify("Invalid password")


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
    global roles

    conn, cur = conn_curr()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(parameter)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allstaff')
def allstaff():
    global roles

    conn, cur = conn_curr()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(2)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allmembers')
def allmembers():
    diction = dict(request.headers)

    global roles

    conn, cur = conn_curr()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(3)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allfinance')
def allfinance():
    global roles

    conn, cur = conn_curr()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(4)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allmanagers')
def allmanagers():
    global roles

    conn, cur = conn_curr()
    all_users = cur.execute('SELECT * from user where role_id = {0}'.format(1)).fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/allusers/')
def allUsers():
    global roles

    conn, cur = conn_curr()
    all_users = cur.execute('SELECT * from user').fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users)


@bp.route('/terminateduser/')
def terminatedUsers():
    global roles

    conn, cur = conn_curr()
    all_users = cur.execute('SELECT * from user where is_terminated=1').fetchall()

    for i in all_users:
        i['role'] = roles[i['role_id']]

    return jsonify(all_users, {})


@bp.route('/updateactivation', methods=['PUT'])
def updateactivation():
    content = flask.request.get_json()

    json_list = []

    conn, cur = conn_curr()

    id = content['id']


    conn.execute('UPDATE user set status=? where id=?', (0, id,))
    conn.commit()
    user = cur.execute('SELECT * from user where id=?', (id,)).fetchone()
    json_list.append(user)

    return jsonify(json_list)


@bp.route('/updateterminated', methods=['PUT'])
def updateterminated(id=None):

    content = flask.request.get_json()

    json_list = []

    conn, cur = conn_curr()

    id = content['id']

    conn.execute('UPDATE user set is_terminated=? where id=?', (1, id,))

    conn.commit()

    user = cur.execute('SELECT * from user where id=?', (id,)).fetchone()

    json_list.append(user)

    return jsonify(json_list)


@bp.route('/updateProfile', methods=['PUT'])
def update_profile():
    if request.method == 'PUT':
        
        conn, cur = conn_curr()
        content = flask.request.get_json()
        json_list = []
        name = content['name']
        user_id = g.user['id']
        phone = content['phone']

        image_id = uuid.uuid4()
        image_path = user_id

        user = cur.execute("SELECT * from user where id=?", (user_id,)).fetchone()
        try:
            image = request.json.get('image')
            data = image.split(';base64,')
            image = data[-1]
            ext = data[0].split('image/')[-1]

            save_image_bs64(image, ext, image_path)

            try:
                conn.execute(
                    'UPDATE images set id=?, url=?, user_id=?,created_at=?',
                    (str(image_id), str(os.path.join(UPLOAD_FOLDER, (image_path + f".{ext}"))), user_id,
                        datetime.datetime.now())
                )
                conn.commit()

            except:
                conn.execute(
                    'INSERT INTO images (id, url, user_id,created_at)'
                    ' VALUES (?, ?, ?, ?)',
                    (str(image_id), str(os.path.join(UPLOAD_FOLDER, (image_path + f".{ext}"))), user_id,
                        datetime.datetime.now())
                )
                conn.commit()

        except :
            print("No image provided")
        
        conn.execute('UPDATE user set name=?,phone=?  where id=? ', (name, phone, user_id,))
        conn.commit()
        user = cur.execute('SELECT * from user where id=?', (user_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)


@bp.route('/userId/<int>:key', methods=['PUT'])
def edit_User(key):
    conn, cur = conn_curr()

    if request.method == 'PUT':

        content = flask.request.get_json()

        json_list = []

        name = content['name']

        user_id = content['id']

        password = content['password']

        email = content['email']

        role_id = content['role_id']

        phone = content['phone']

        try:

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

                user = cur.execute("SELECT * from user where id=?", (user_id,)).fetchone()
                try:

                    conn.execute(
                        'UPDATE images set id=?, url=?, user_id=?,created_at=?',
                        (str(image_id), str(os.path.join(UPLOAD_FOLDER, (image_path + ".jpeg"))), user_id,
                         datetime.datetime.now())
                    )
                    conn.commit()

                except:
                    conn.execute(
                        'INSERT INTO images (id, url, user_id,created_at)'
                        ' VALUES (?, ?, ?, ?)',
                        (str(image_id), str(os.path.join(UPLOAD_FOLDER, (image_path + ".jpeg"))), user_id,
                         datetime.datetime.now())
                    )
                    conn.commit()
        except:

            print('No Image')

        conn.execute('UPDATE user set name=?,phone=?,role_id=?,password=?,email=?   where id=? ',
                     (name, phone, role_id, generate_password_hash(password), email, user_id,))
        conn.commit()

        user = cur.execute('SELECT * from user where id=?', (user_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)


@bp.route('/deleteuser', methods=['DELETE'])
def deletex():

    content = flask.request.get_json()

    json_list = []

    conn, cur = conn_curr()

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
        contact = content['phone']
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
            try:
                image = request.json.get('image')
                data = image.split(';base64,')
                image = data[-1]
                ext = data[0].split('image/')[-1]

                if image != "NULL":
                    save_image_bs64(image, ext, str(id))
                    user = cur.execute("SELECT * from user where email=?", (email,)).fetchone()
                    conn.execute(
                        'INSERT INTO images (id, url, user_id,created_at)'
                        ' VALUES (?, ?, ?, ?)',
                        (str(id), str(os.path.join(UPLOAD_FOLDER, (str(id) + "." + str(ext)))), user['id'],
                         datetime.datetime.now())
                    )
                    conn.commit()
            except:
                print("Image not given")

                # send_email(email, verification_code)
            user = cur.execute("SELECT * from user where email=?", (email,)).fetchone()
            del user['password']

            return jsonify({"status": "success", "data": user})

    return jsonify({"message": "Unauthorized"}), 403

def save_image_bs64(image, ext, image_path):
    image = image.encode('utf-8')
    decode_image = base64.decodebytes(image + b'===')
    image = decode_image
    file = open(os.path.join(UPLOAD_FOLDER, (image_path + "." + str(ext))), 'wb')
    file.write(image)
    file.close()



@bp.route('/login', methods=['POST'])
def login():
    if request.method == "POST":
        content = flask.request.get_json()
        conn, cur = conn_curr()

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
                data = {"user": user, "token": token, "success": True, }
                return jsonify(data)


@bp.route('/logout')
def logout():
    responseObject = {
        'status': 'success',
        'message': 'Successfully logged out.'
    }
    return make_response(jsonify(responseObject)), 200


@bp.route('/createRequest', methods=['POST'])
def create_request():
    if request.method == "POST" and g.user['role_id'] not in [1, 4]:
        conn, cur = conn_curr()
        content = flask.request.get_json()
        user_id = g.user['id']
        request_id = str(uuid.uuid4())
        items_array = content['items']
        content = items_array

        user = g.user
        staff_id = None
        if user['role_id'] == 3:
            status = 'Pending'
            conn.execute(
                'INSERT INTO request(_id,user_id,created_at,status,order_created, staff_id) '
                'VALUES (?,?,?,?,?,?)',
                (str(request_id), user_id, datetime.datetime.now(), status, None, staff_id))
            conn.commit()
        else:
            staff_id = user["id"]
            status = 'Processing'
            conn.execute(
                'INSERT INTO request(_id,user_id,created_at,status,order_created, staff_id) '
                'VALUES (?,?,?,?,?,?)',
                (str(request_id), user_id, datetime.datetime.now(), status, True, staff_id))
            conn.commit()

        for i in range(len(items_array)):
            content_items = content[int(i)]
            name = content_items['name']
            description = content_items['description']
            quantity = content_items['quantity']
            items_id = uuid.uuid4()
            requests = cur.execute("SELECT * from request WHERE _id=?",
                                (request_id,)).fetchone()
            print(requests)
            conn.execute(
                'INSERT INTO items(id,name,description,price,request_id,created_at,quantity) '
                'VALUES (?,?,?,?,?,?,?)',
                (str(items_id), name, str(description), "0", requests['_id'], datetime.datetime.now(), quantity,))
            conn.commit()
        items = cur.execute("SELECT * from items WHERE request_id=?",
                            (request_id,)).fetchall()
        requests["items"] = items
        return jsonify([requests])


@bp.route('/userRequests', methods=['GET'])
def user_requests():
    if request.method == "GET" and g.user['role_id'] == 3:
        conn, cur = conn_curr()
        total_request = cur.execute('SELECT * from request where user_id=? ',(g.user['id'],)).fetchall()
        for i in range(len(total_request)):
            items = cur.execute('SELECT * from items where request_id=? ',(total_request[i]['_id'],)).fetchall()
            total_request[i]['items'] = items
        return jsonify(total_request)

@bp.route('/user', methods=['GET'])
def user():
    return jsonify({"data":g.user})


@bp.route('/process-requests/request-details?requestId=<int:request_id>', methods=['POST', 'GET'])
def assign_request(request_id=None):
    if request.method == 'POST':

        conn, cur = conn_curr()

        content = flask.request.get_json()
        staff_id = content['staff_id']

        request_id = request_id

        json_list = []

        conn.execute('UPDATE request set staff_id=?, status=? where id=?', (staff_id, 'Processing', request_id,))
        conn.commit()
        user = cur.execute('SELECT * from items where request_id=?', (request_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)

    else:

        conn, cur = conn_curr()

        content = flask.request.get_json()

        request_id = content['id']

        items = cur.execute('SELECT * from items where request_id=?', (request_id,)).fetchone()

        return jsonify(items)


@bp.route('/new-requests/request-details?requestId=<int:id>', methods=['POST', 'GET'])
def read_request(id=None):
    if request.method == 'POST':

        conn, cur = conn_curr()

        content = flask.request.get_json()

        request_id = content['id']

        json_list = []

        user = cur.execute('SELECT * from items, request where request_id=? and request.status="Pending"',
                           (request_id,)).fetchone()

        json_list.append(user)

        return jsonify(json_list)

    else:

        conn, cur = conn_curr()

        items = cur.execute('SELECT * from items,request where items.request_id=request._id and '
                            'request.status="Pending" or request.status="Quotes Added" ').fetchall()
        return jsonify(items)


@bp.route('/approved-requests/request-details?requestId=<int:id>', methods=['POST'])
@bp.route('/approved-requests', defaults={'id': None}, methods=['GET'])
def approved_request(id=None):
    if request.method == 'POST':

        conn, cur = conn_curr()

        content = flask.request.get_json()

        request_id = content['id']

        json_list = []

        user = cur.execute('SELECT * from items, request where request_id=? and request.status="Approved"',
                           (request_id,)).fetchone()

        json_list.append(user)

        return jsonify(json_list)

    else:

        conn, cur = conn_curr()

        items = cur.execute('SELECT * from items,request where items.request_id=request._id and '
                            'request.status="Approved"').fetchall()
        return jsonify(items)


@bp.route('/createquotes/<string:request_id>', methods=['POST'])
def create_quote(request_id=None):
    if request.method == "POST" and g.user['role_id'] == 2:

        conn, cur = conn_curr()

        if 'file' not in request.files:
            return jsonify('No Quote has been added')

        files = request.files.getlist("files")

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
    conn, cur = conn_curr()

    json_list = []

    user = cur.execute('SELECT * from quotes where status<>"Approved"').fetchall()
    json_list.append(user)

    return jsonify(json_list)


@bp.route('orders/order-details?orderId=<int:id>', methods=['POST', 'GET'])
@bp.route('/orders', defaults={'id': None}, methods=['GET'])
def all_quotes_verified(id=None):
    if id is None:
        conn, cur = conn_curr()

        json_list = []

        user = cur.execute('SELECT * from orders').fetchall()
        json_list.append(user)

        return jsonify(json_list)

    else:

        if request.method == 'GET':

            conn, cur = conn_curr()

            content = flask.request.get_json()

            order_id = content['order_id']

            comment = content['comment']

            json_list = []

            conn.execute('UPDATE orders is_sign=?, comment=?  where id=?', (True, comment, order_id,))
            conn.commit()
            user = cur.execute('SELECT * from orders where id=?', (order_id,)).fetchone()
            json_list.append(user)

            return jsonify(json_list)


        else:
            conn, cur = conn_curr()

            json_list = []

            user = cur.execute('SELECT * from orders where id=?', (id)).fetchone()
            json_list.append(user)

            return jsonify(json_list)


@bp.route('/approvequote', methods=['POST', 'GET'])
def approve_quote():
    if request.method == 'POST':

        conn, cur = conn_curr()

        content = flask.request.get_json()

        request_id = content['id']

        json_list = []

        conn.execute('UPDATE quotes status=? where request_id=?', ('Approved', request_id,))
        conn.commit()
        user = cur.execute('SELECT * from quotes where request_id=?', (request_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)

    else:

        conn, cur = conn_curr()

        content = flask.request.get_json()

        request_id = content['id']

        items = cur.execute('SELECT * from quotes where request_id=?', (request_id,)).fetchone()

        return jsonify(items)


@bp.route('/createordersfromstaff', methods=['POST'])
def create_orders_from_staff():
    if request.method == "POST":

        conn, cur = conn_curr()

        if 'file' not in request.files:
            return jsonify('No Quote has been added')

        files = request.files.getlist("files")
        content = request.form

        items_array = content['items']

        request_id = content['request_id']

        total = content['total']

        is_cash = False

        for file in files:
            if file and allowed_file(file.filename):
                file.save(os.path.join(UPLOAD_FOLDER, secure_filename(file.filename)))

                conn.execute(
                    'INSERT INTO orders (id, items,request_id, total, staff_id, is_sign ,path,created_at, is_cash, '
                    'is_read, '
                    'comment) '
                    ' VALUES (?, ?, ?, ?,?,?,?,?,?,?,?)',
                    (str(uuid.uuid4()), str(items_array), request_id, total, g.user['id'], False,
                     os.path.join(UPLOAD_FOLDER, secure_filename(file.filename)), datetime.datetime.now(),
                     is_cash, False)
                )
                conn.commit()

        return jsonify("Order has been added")


@bp.route('/createpurchaseorder', methods=['POST'])
def create_purchase_order():
    if request.method == "POST":

        conn, cur = conn_curr()
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

        conn, cur = conn_curr()

        diction = dict(request.headers)

        content = flask.request.get_json()

        is_read = content['is_read']

        order_id = order_id

        json_list = []

        conn.execute('UPDATE orders is_read=? where id=? and is_sign=True ', (is_read, order_id,))
        conn.commit()
        user = cur.execute('SELECT * from orders where id=?', (order_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)

    else:

        conn, cur = conn_curr()

        orders = cur.execute('SELECT * from orders where is_sign=True').fetchall()

        return jsonify(orders)


@bp.route('/approveorderfrommanager', methods=['POST', 'GET'])
def approve_ordermanager():
    if request.method == 'POST':

        conn, cur = conn_curr()

        content = flask.request.get_json()

        order_id = content['order_id']

        comment = content['comment']

        json_list = []

        conn.execute('UPDATE orders is_sign=?, comment=?  where id=?', (True, comment, order_id,))
        conn.commit()
        user = cur.execute('SELECT * from orders where id=?', (order_id,)).fetchone()
        json_list.append(user)

        return jsonify(json_list)

    else:

        conn, cur = conn_curr()

        orders = cur.execute('SELECT * from orders where is_sign=False ').fetchall()

        return jsonify(orders)


@bp.route('/dashboard', methods=['GET'])
def dashboard():
    conn, cur = conn_curr()

    count_total_request = cur.execute('SELECT COUNT(*) from request').fetchall()

    count_new_request = cur.execute('SELECT COUNT(*) from request where request.status="Pending"').fetchall()

    count_processing_request = cur.execute('SELECT COUNT(*) from request where request.status="Processing"').fetchall()

    return jsonify({'totalRequests': count_total_request[0]["COUNT(*)"], 'pending': count_new_request[0]["COUNT(*)"],
                    'waitingForApproval': count_processing_request[0]["COUNT(*)"], 'success': True})


@bp.route('/totalrequests')
def total_request():
    conn, cur = conn_curr()

    total_request = cur.execute('SELECT * from request').fetchall()

    return jsonify(total_request)


@bp.route('/newrequests')
def new_total_request():
    conn, cur = conn_curr()

    new_request = cur.execute('SELECT * from request where request.status="Pending"').fetchall()

    return jsonify(new_request)


@bp.route('/processingrequests')
def processing_total_request():
    conn, cur = conn_curr()

    processing_request = cur.execute('SELECT * from request where request.status="Processing"').fetchall()

    return jsonify(processing_request)
