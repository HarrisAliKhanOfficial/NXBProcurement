import base64
import datetime
import json
import os
import uuid

import flask
import jwt
import pandas as pd
from flask import Blueprint, request, url_for, jsonify, make_response, g
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash

from App import UPLOAD_FOLDER, priv_key
from App import sign_image
from . import db

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
bp = Blueprint('api', __name__, url_prefix="/api")
mail = Mail()

global roles
roles = {1: 'Manager', 2: 'Staff', 3: 'User', 4: 'Finance'}


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
        if isinstance(token, (bytes, bytearray)):
            return token.decode('utf-8')
        else:
            return token
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
        conn.execute('UPDATE user set password=? where user.id=?', (generate_password_hash(password), g.user['id'],))
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


@bp.route('/allUsers')  # include everyone
@bp.route('/getFinanceMembers')
@bp.route('/allManagers')
@bp.route('/getUsers')
@bp.route('/getStaffMembers')
def users():
    global roles
    conn, cur = conn_curr()
    request_name = request.url.split("/")[-1]
    query = 'SELECT * from user '
    if request_name == "allUsers":
        query += "where role_id<>1 and status<>0"
    elif request_name == "getFinanceMembers":
        query += "where role_id=4 and status<>0"
    elif request_name == "getUsers":
        query += "where role_id=3 and status<>0"
    elif request_name == "getStaffMembers":
        query += "where role_id=2 and status<>0"
    else:
        query += "where role_id=1 and status<>0"
    all_users = cur.execute(query).fetchall()
    for i in all_users:
        i['role'] = roles[i['role_id']]
        del i['password']
    return jsonify(all_users)


@bp.route('/allterminatedusers/')
def terminatedUsers():
    global roles
    conn, cur = conn_curr()
    all_users = cur.execute('SELECT * from user where is_terminated=1').fetchall()
    for i in all_users:
        i['role'] = roles[i['role_id']]
        del i['password']
    return jsonify(all_users)


@bp.route('/toggleActivation', methods=['PUT'])
def updateactivation():
    content = flask.request.get_json()
    json_list = []
    conn, cur = conn_curr()
    id = content['id']
    user = cur.execute('SELECT * from user where id=?', (id,)).fetchone()

    if user['status']==True:
        status = False
    else:
        status = True

    conn.execute('UPDATE user set status=? where id=?', (status, id,))
    conn.commit()
    user = cur.execute('SELECT * from user where id=?', (id,)).fetchone()
    json_list.append(user)
    return jsonify(json_list)


@bp.route('/terminateUser', methods=['POST',"PUT"])
def updateterminated(id=None):
    content = flask.request.get_json()
    conn, cur = conn_curr()
    id = content['id']
    conn.execute('UPDATE user set is_terminated=? where id=?', (1, id,))
    conn.commit()
    return 200


@bp.route('/updateProfile', methods=['PUT'])
def update_profile():
    return update_user(g.user['id'])


@bp.route('/updateUserAndStaff/<key>', methods=['PUT'])
def edit_User(key):
    return update_user(key)


def update_user(user_id):
    conn, cur = conn_curr()
    content = flask.request.get_json()
    json_list = []
    name = content['name']
    phone = content['phone']
    role_id = content.get("role_id")
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
            conn.execute('INSERT INTO images (id, url, user_id,created_at)'
                         ' VALUES (?, ?, ?, ?)',
                         (str(image_id), str(os.path.join(UPLOAD_FOLDER, (image_path + f".{ext}"))), user_id,
                          datetime.datetime.now()))
            conn.commit()

    except:
        print("No image provided")
    if g.user['role_id'] == 1:
        conn.execute('UPDATE user set name=?,phone=?,role_id=?  where id=? ', (name, phone, role_id, user_id,))
    else:
        conn.execute('UPDATE user set name=?,phone=?  where id=? ', (name, phone, user_id,))
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




@bp.route('/deleteOrderOrPurchase/',defaults={'order_id' : None}, methods=['DELETE'])
def deleteorderorPurchase(order_id):
    conn, cur = conn_curr()

    conn.execute('DELETE FROM order where id=? and sign=0', (str(order_id),))
    conn.commit()

    return jsonify("Order has been deleted")





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
            # try:
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
            # except:
            #     print("Image not given")

                # send_email(email, verification_code)
            user = cur.execute("SELECT * from user where email=?", (email,)).fetchone()
            del user['password']

            return jsonify({"status": "success", "data": user})

    return jsonify({"message": "Unauthorized"}), 403


def save_image_bs64(image, ext, image_path):
    image = image.encode('utf-8')
    decode_image = base64.decodebytes(image + b'===')
    image = decode_image
    if not os.path.exists(os.getcwd()+'/App/uploads/userImages/' ):
        os.makedirs( os.getcwd()+'/App/uploads/userImages/' )

    UPLOAD_FOLDER = str(os.getcwd() + '/App/uploads/userImages/')

    file = open(os.path.join(UPLOAD_FOLDER, (image_path + "." + str(ext))), 'wb')
    file.write(image)
    file.close()


@bp.route('/login', methods=['POST'])
def login():
    if request.method == "POST":
        content = flask.request.get_json()
        conn, cur = conn_curr()
        email = content.get('email')
        password = content.get('password')

        if email is None or password is None or id is None:
            return jsonify("Email or password cannot be null"), 401
        else:
            pass_check = cur.execute('SELECT * from user where user.email=?', (email,)).fetchone()
            if not pass_check:
                return jsonify('Please verify your email address')
            elif not check_password_hash(pass_check['password'], password):
                return jsonify("Password Incorrect")
            else:
                user = cur.execute("SELECT * from user WHERE email=?",
                                   (email,)).fetchone()
                token = encode_token(user['id'])
                user.pop("password")
                data = {"user": user, "token": token, "success": True}
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

        if 'file' in request.files:

            files = request.files.getlist("file")

            for file in files:
                file_name = str(file.filename).split(".")
                file_name = "." + file_name[-1]
                image_id = str(uuid.uuid4())

                file.save(os.path.join(UPLOAD_FOLDER, image_id + file_name))

                df = pd.read_csv(os.path.join(UPLOAD_FOLDER, image_id + file_name))
                content = {}
                for row in range(len(str(df['name']))):
                    try:
                        content[row] = ({"items": {"name": str(df['name'][row]), "quantity": str(df['quantity'][row]),
                                                   "description": str(df['description'][row])}})
                    except:
                        pass
                items_array = content
        else:
            items_array = content['items']

        content = items_array

        user = g.user
        staff_id = None
        if user['role_id'] == 3:
            status = 'Pending'
            conn.execute(
                'INSERT INTO request(_id,user_id,created_at,status,order_created, staff_id) '
                'VALUES (?,?,?,?,?,?)',
                (str(request_id), user_id, datetime.datetime.now(), status, False, staff_id))
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
            try:
                name = content_items['name']
                description = content_items['description']
                quantity = content_items['quantity']
            except:
                name = content_items['items']['name']
                description = content_items['items']['description']
                quantity = content_items['items']['quantity']

            items_id = uuid.uuid4()
            requests = cur.execute("SELECT * from request WHERE _id=?",
                                   (request_id,)).fetchone()

            conn.execute(
                'INSERT INTO items(id,name,description,price,request_id,created_at,quantity) '
                'VALUES (?,?,?,?,?,?,?)',
                (str(items_id), name, str(description), "0", requests['_id'], datetime.datetime.now(), quantity,))
            conn.commit()
        items = cur.execute("SELECT * from items WHERE request_id=?",
                            (request_id,)).fetchall()
        requests["items"] = items
        return jsonify([requests])
    return jsonify("Not Authorized"), 401


@bp.route('/userRequests', methods=['GET'])
def user_requests():
    if request.method == "GET" and g.user['role_id'] in [2, 3]:
        conn, cur = conn_curr()
        total_request = cur.execute('SELECT * from request where user_id=? ', (g.user['id'],)).fetchall()
        return jsonify(attach_items_to_request('items', total_request))
    return jsonify("Not Authorized"), 401


def attach_items_to_request(table, total_request):
    conn, cur = conn_curr()
    for i in range(len(total_request)):
        items = cur.execute(f"SELECT * from {table} where request_id=? ", (str(total_request[i]['_id']),)).fetchall()
        total_request[i][table] = items
    return total_request

@bp.route('/getUserAndStaff/', defaults={'staff_id': None}, methods=['GET'])
@bp.route('/user', methods=['GET'])
def user(staff_id=None):
    user = g.user
    if staff_id:
        cur, conn = conn_curr()
        query = f"Select * from user where id='{staff_id}'"
        user = cur.execute(query).fetchone()
    del user['password']
    return jsonify({"data": g.user})


@bp.route('/requests/<request_id>', methods=['GET'])
@bp.route('/assignrequests/<request_id>', methods=['POST'])
def assign_request(request_id=None):
    conn, cur = conn_curr()
    if request.method == 'POST':
        content = flask.request.get_json()
        staff_id = content.get('staff_id')

        if not request_id or not staff_id:
            return jsonify("Provide the Staff and Request Id")

        conn.execute('UPDATE request set staff_id=?, status=? where _id=?', (staff_id, 'Processing', request_id,))
        conn.commit()
        requests = cur.execute('SELECT request.*,user.name from request,user where _id=? and request.staff_id=user.id',
                               (request_id,)).fetchone()
        return jsonify({"request": requests, "message": "Success"})
    else:
        if not request_id:
            return jsonify("Provide the Request ID")
        try:
            requests = cur.execute(
                'SELECT request.*,user.name from request,user where _id=? and request.staff_id=user.id',
                (request_id,)).fetchone()
            requests = attach_items_to_request('items', [requests])[0]
            return jsonify(requests)
        except:
            return jsonify("The request Id is invalid")


@bp.route('/new-requests/request-details?requestId=<int:id>', methods=['POST', 'GET'])
def read_request(id=None):
    conn, cur = conn_curr()
    if request.method == 'POST':
        content = flask.request.get_json()
        request_id = content['id']
        user = cur.execute('SELECT * from items, request where request_id=? and request.status="Pending"',
                           (request_id,)).fetchone()
        return jsonify(user)
    else:
        items = cur.execute('SELECT * from items,request where items.request_id=request._id and '
                            'request.status="Pending" or request.status="Quotes Added" ').fetchall()
        return jsonify(items)


@bp.route('/approved-requests/request-details?requestId=<int:id>', methods=['POST'])
@bp.route('/requests/<id>', defaults={'id': None}, methods=['GET'])  # get specific request
def approved_request(id=None):
    conn, cur = conn_curr()
    if request.method == 'POST':
        content = flask.request.get_json()
        request_id = content['id']
        json_list = []
        user = cur.execute('SELECT * from items, request where request_id=? and request.status="Approved"',
                           (request_id,)).fetchall()
        json_list.append(user)
        return jsonify(json_list)
    else:
        items = cur.execute('SELECT * from items,request where items.request_id=request._id and '
                            'request.status="Approved"').fetchall()
        return jsonify(items)


@bp.route('/uploadQuotesByStaff/<request_id>', methods=['POST'])
def create_quote(request_id=None):
    conn, cur = conn_curr()
    if request.method == "POST" and g.user['role_id'] == 2:
        if 'files' not in request.files:
            return jsonify({"files": ["The files field is required."]}), 422
        files = request.files.getlist("files")
        for file in files:
            file_name = str(file.filename).split(".")
            file_name = "." + file_name[-1]
            image_id = str(uuid.uuid4())
            image_path = os.getcwd()
            if not os.path.exists(os.getcwd()+'/App/uploads/quotes/'  ):
                os.makedirs(os.getcwd() + '/App/uploads/quotes/')
            UPLOAD_FOLDER = str(os.getcwd() + '/App/uploads/quotes/')

            file.save(os.path.join(UPLOAD_FOLDER, image_id + file_name))
            conn.execute(
                'INSERT INTO quotes (id, path, request_id,status,created_at)'
                ' VALUES (?, ?, ?, ?,?)',
                (image_id, os.path.join(UPLOAD_FOLDER, image_id + file_name), request_id,
                 "Quotes "
                 "Added",
                 datetime.datetime.now())
            )
            conn.commit()
        return jsonify({"Message": "Success"}), 201


@bp.route('/allquotes', methods=['GET'])
def all_quotes():
    conn, cur = conn_curr()

    quotes = cur.execute('SELECT * from quotes where status<>"Approved"').fetchall()

    return jsonify(quotes)

@bp.route('/readCashOrders', methods=['GET'])
@bp.route('/orders', methods=['GET'])
@bp.route('/staffAllCashOrders', methods=['GET'])
@bp.route('/allCashOrders', methods=['GET'])
@bp.route('/staffAllOrders', methods=['GET'])
@bp.route('/orders/', defaults={'order_id': None}, methods=['GET'])
def all_quotes_verified(order_id=None):
    conn, cur = conn_curr()
    request_name = request.url.split("/")[-1]
    if request_name == 'allCashOrders':
        orders = cur.execute(
            'SELECT * from orders,user where user.id=orders.staff_id and orders.request_id IS NULL').fetchall()
        orders = items_json(orders)
    elif request_name == 'staffAllCashOrders':
        orders = cur.execute(
            f'SELECT * from orders,user where user.id=orders.staff_id and orders.request_id IS NULL and orders.staff_id="{g.user["id"]}"').fetchall()
        orders = items_json(orders)
    elif request_name == 'staffAllOrders':
        orders = cur.execute(
            f'SELECT * from orders,user where user.id=orders.staff_id and orders.request_id IS NOT NULL and orders.staff_id="{g.user["id"]}"').fetchall()
        orders = items_json(orders)
    elif request_name == 'readCashOrders':
        orders = cur.execute(
            f'SELECT * from orders,user where user.id=orders.staff_id and orders.request_id IS NULL').fetchall()
        orders = items_json(orders)
    else:

        if g.user['role_id'] == 1:
            query = f'SELECT * from orders where id="{order_id}"'
        else:
            query = f'SELECT * from orders where id="{order_id}" and staff_id= "{g.user["id"]}" '
        orders = cur.execute(query).fetchone()
        try:
            orders['items'] = json.loads(orders['items'])
        except:
            return jsonify("Order Id is Incorrect or Not provided")

    return jsonify(orders)

@bp.route('allapprovedrequests', methods=['GET'])
@bp.route('/approvedquote', methods=['POST','GET'])
def approve_quote():
    conn, cur = conn_curr()
    if request.method =="POST":
        content = flask.request.get_json()
        quote_id = content['quote_id']
        conn.execute("UPDATE quotes set status=? where id=? and status=?", ("Approved", quote_id, "Quotes Added"))
        conn.commit()
        quote = cur.execute('SELECT * from quotes where id=?', (quote_id,)).fetchone()
        return jsonify({"Message": "Success", "quote": quote})
    else:
        quotes = cur.execute('SELECT * from quotes where status="Approved"').fetchall()

        return jsonify(quotes)


@bp.route('/createOrder', methods=['POST'])
@bp.route('/createCashOrder', methods=['POST'])
def create_orders_from_staff():
    conn, cur = conn_curr()
    request_name = request.url.split("/")[-1]
    if request_name == 'createOrder':
        is_cash = False
    else:
        is_cash = True
    if 'files' not in request.files:
        return jsonify('No Quote has been added')

    files = request.files.getlist("files")
    content = request.form

    items_array = content.get('items')
    request_id = content.get('request_id')
    total = content.get('total')

    if not items_array or not total:
        return jsonify("Missing arguments"), 422
    order_id = str(uuid.uuid4())

    for file in files:
        file_name = str(file.filename).split(".")
        file_name = "." + file_name[-1]
        image_id = str(uuid.uuid4())
        file.save(os.path.join(UPLOAD_FOLDER, image_id + file_name))

        image_path = os.getcwd()
        if not os.path.exists(os.getcwd()+  '/App/uploads/bills/' ):
            os.makedirs(os.getcwd() + '/App/uploads/bills/')
        UPLOAD_FOLDER = str(os.getcwd() + 'App/uploads/bills/')

        conn.execute('INSERT INTO images (id, url, user_id,created_at)'
                     ' VALUES (?, ?, ?, ?)',
                     (image_id, str(os.path.join(UPLOAD_FOLDER, image_id + file_name)), order_id,
                      datetime.datetime.now(),))
        conn.commit()
    conn.execute(
        'INSERT INTO orders (id, items,request_id, total, staff_id, is_sign ,created_at, is_cash, '
        'is_read) '
        ' VALUES (?,?,?,?,?,?,?,?,?)',
        (order_id, str(items_array), request_id, total, g.user['id'], False, datetime.datetime.now(),
         is_cash, False)
    )
    conn.commit()
    conn.execute('UPDATE request set status="Order Created", order_created=True where _id=? ', (request_id,))
    conn.commit()

    order = cur.execute("SELECT * from orders, request where orders.id=?", (order_id,)).fetchone()
    order['images'] = get_order_image(order_id)
    order['items'] = json.loads(order['items'])
    return jsonify([order])


def get_order_image(order_id):
    conn, cur = conn_curr()
    return cur.execute("SELECT images.url from images, orders where orders.id=? and orders.id=images.user_id",
                       (order_id,)).fetchall()


@bp.route('/allCashOrdersFinance', methods=['GET'])
@bp.route('/readOrders', methods=['GET'])
@bp.route('/allOrders', methods=['GET'])
@bp.route('/signedOrderForFinance', methods=['GET'])
@bp.route('/markAsRead/<order_id>', methods=['POST'])
def approve_orderfinance(order_id=None):
    conn, cur = conn_curr()
    is_read = 0
    if request.method == 'POST':
        content = flask.request.get_json()
        is_read = content['is_read']
        conn.execute('UPDATE orders set is_read=? where id=? and is_sign=1 ', (is_read, order_id,))
        conn.commit()
        user = cur.execute('SELECT * from orders where id=?', (order_id,)).fetchone()
        return jsonify({"Message": "Order marked as read."})
    else:
        request_name = request.url.split("/")[-1]
        if request_name == 'readOrders':
            is_read = 1

        elif request_name == 'allCashOrdersFinance':
            orders = cur.execute(
                f'SELECT * from orders where is_sign=1 and is_read={is_read} and orders.request_id IS NULL').fetchall()
            orders = items_json(orders)
            return jsonify(orders)
        elif request_name == 'allOrders':
            orders = cur.execute('SELECT * from orders').fetchall()
            orders = items_json(orders)
            return jsonify(orders)
        else:
            pass

        orders = cur.execute(f'SELECT * from orders where is_sign=1 and is_read={is_read}').fetchall()
        orders = items_json(orders)
        return jsonify(orders)


def items_json(orders):
    for i in range(len(orders)):
        orders[i]['images'] = get_order_image(orders[i]['id'])
        orders[i]['items'] = json.loads(orders[i]['items'])
    return orders


@bp.route('/allUnsignedOrders', methods=['GET'])
@bp.route('/digitalSign', methods=['POST'])
def approve_ordermanager():
    conn, cur = conn_curr()
    if g.user['role_id'] not in [1]:
        return jsonify("Unauthorized user"), 401
    if request.method == 'POST':
        content = flask.request.get_json()
        order_id = content['order_id']
        comment = content.get('comment', "")
        conn.execute('UPDATE orders set is_sign=?, comment=?  where id=?', (True, comment, order_id,))
        conn.commit()
        user = cur.execute('SELECT * from orders where id=?', (order_id,)).fetchone()

        images = get_order_image(order_id)
        for image in images:
            sign_image.add_signarture(image['url'])

        return jsonify({"Message": "Success"}), 201
    else:
        orders = cur.execute('SELECT * from orders where is_sign<>1 ').fetchall()
        return jsonify(orders)


@bp.route('/dashboard', methods=['GET'])
def dashboard():
    conn, cur = conn_curr()
    count_total_request = cur.execute('SELECT COUNT(*) from request').fetchall()
    count_new_request = cur.execute('SELECT COUNT(*) from request where request.status="Pending"').fetchall()
    count_processing_request = cur.execute('SELECT COUNT(*) from request where request.status="Processing"').fetchall()
    return jsonify({'totalRequests': count_total_request[0]["COUNT(*)"], 'pending': count_new_request[0]["COUNT(*)"],
                    'waitingForApproval': count_processing_request[0]["COUNT(*)"], 'success': True})


@bp.route('/totalrequests', methods=['GET'])
def total_request():
    return jsonify(pms_requests())


@bp.route('/totalrequestscheck', methods=['GET'])
def total_request_check():
    conn, cur = conn_curr()
    total_request = cur.execute('SELECT * from request,items where user_id=? and items.request_id=request._id ',
                                (g.user['id'],)).fetchall()
    return jsonify(total_request)


@bp.route('/allnewrequests', methods=['GET'])
def new_total_request():
    status = 'Pending'
    processing = pms_requests({"status": status})
    items_attached = attach_items_to_request('items', processing)
    quotes_attached = attach_items_to_request('quotes', items_attached)
    return jsonify(items_attached)


@bp.route('/allinprocessrequests', methods=['GET'])
def processing_total_request():
    status = 'Processing'
    processing = pms_requests({"status": status})
    items_attached = attach_items_to_request('items', processing)
    quotes_attached = attach_items_to_request('quotes', items_attached)
    return jsonify(quotes_attached)


def pms_requests(params_dict=None, table="request"):
    conn, cur = conn_curr()
    query = f"SELECT * from {table} "
    if params_dict:
        query += "where "
        for i in params_dict:
            query += f"{i} = '{params_dict[i]}' and "
        query = query[:-4]
    print(query)
    return cur.execute(query).fetchall()


@bp.route('/staffnewrequests', methods=['GET'])
def staff_request():
    status = 'Processing'
    all_staff_requests = pms_requests({"status": status, "staff_id": g.user['id']})
    items_attached = attach_items_to_request('items', all_staff_requests)
    quotes_attached = attach_items_to_request('quotes', items_attached)
    return jsonify(quotes_attached)
