import datetime
import hashlib
import hmac
import json
import math
import random
import string
from turtle import pd
from PIL import Image
from flask import request, redirect, render_template, jsonify, url_for, session, flash
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.exc import IntegrityError
from SIC import app, dao, login,db, utils, loaded_model, scaler
from SIC.dao import get_patient_by_id
from SIC.decorators import roles_required, cashiernotloggedin, adminloggedin, resources_owner
from SIC.forms import PrescriptionForm, ChangePasswordForm, EditProfileForm, ChangeAvatarForm, ChangeUsernameForm
from SIC.models import UserRole, Gender, AppointmentList
from flask_mail import Mail, Message

from SIC.vnpay import vnpay

mail = Mail(app)


@app.template_filter()
def numberFormat(value):
    return format(int(value), ',d')


@app.route('/')
@adminloggedin
def index():  # put application's code here
    return render_template('index.html')


@app.route('/login', methods=['get', 'post'])
def login_my_user():
    err_msg = None
    if current_user.is_authenticated:
        return redirect('/')  # Đã đăng nhập, chuyển hướng đến trang chính
    if request.method.__eq__('POST'):
        username = request.form.get('username')
        password = request.form.get('password')
        user = dao.auth_user(username=username, password=password)
        if user:
            login_user(user)

            next = request.args.get('next')
            if current_user and current_user.role == UserRole.ADMIN:
                return redirect('/admin')
            return redirect(next if next else '/')
        else:
            err_msg = 'Username hoặc password không đúng!'

    return render_template('auth/login.html', err_msg=err_msg)


@app.route("/admin-login", methods=['post'])
def process_admin_login():
    username = request.form.get('username')
    password = request.form.get('password')
    u = dao.auth_user(username=username, password=password)
    if u and u.role == UserRole.ADMIN:
        login_user(user=u)
    return redirect('/admin')


@app.route('/logout', methods=['get'])
def logout_my_user():
    logout_user()
    return redirect('/login')


@app.route('/check_username', methods=['POST'])
def check_username():
    data = request.json

    if 'username' not in data:
        return jsonify({'error': 'Missing username parameter'}), 400

    username = data['username']

    if dao.get_user_by_username(username) is not None:
        return jsonify({'message': 'Username exists'}), 409
    else:
        return jsonify({'message': 'Username valid'}), 200


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    err_msg = None
    avatar_url = None
    if request.method.__eq__('POST'):
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        if password.__eq__(confirm):
            avatar = request.files.get('avatar')
            if avatar:
                if avatar.filename != '':
                    img = Image.open(avatar)
                    img_cropped = utils.crop_to_square(img)
                    avatar_url = utils.upload_image_to_cloudinary(img_cropped)
                    if avatar_url:
                        pass
                    else:
                        flash('Đã xảy ra lỗi khi tải lên hình ảnh.', 'danger')
                        avatar_url = "https://www.shutterstock.com/image-vector/default-avatar-profile-icon-social-600nw-1677509740.jpg"
                        return redirect(url_for('register_user'))

            gender = None
            if request.form.get('gender') == 'male':
                gender = Gender.MALE
            else:
                gender = Gender.FEMALE
            try:
                session['patient_cid'] = request.form.get('cid')
                current_user_role = session.pop('current_user_role', None)
                email = request.form.get('email')
                username = request.form.get('username')
                name = request.form.get('name')
                dao.add_user(name=name,
                             username=username,
                             password=password,
                             avatar=avatar_url,
                             email=email,
                             phone=request.form.get('phone'),
                             address=request.form.get('address'),
                             cid=request.form.get('cid'),
                             dob=request.form.get('dob'),
                             gender=gender
                             )
                if current_user_role == 'nurse':
                    send_account_email(email, username, password, name)
                    return redirect('/nurse/nurse_book')
            except IntegrityError as ie:
                if ie.orig.args[0] == 1062:
                    ieMessage = ie.orig.args[1].split()
                    entry = ieMessage[len(ieMessage) - 1]
                    if entry == '\'user.username\'':
                        return redirect(url_for('register_user', err_msg=f'Mã lỗi: 409; Lỗi: Username có rồi!!!'))
                    if entry == '\'user.ix_user_cid\'':
                        return redirect(
                            url_for('register_user', err_msg=f'Mã lỗi: 409; Lỗi: Căng Cước Công Dân này có rồi!!!'))
                    if entry == '\'user.email\'':
                        return redirect(url_for('register_user', err_msg=f'Mã lỗi: 409; Lỗi: Email này có rồi!!!'))

                return redirect(url_for('register_user', err_msg=f'Mã lỗi: {ie.orig.args[0]}; Lỗi: {ie.orig.args[1]}'))
            except Exception as e:
                return redirect(url_for('register_user', err_msg=str(e)))

            return redirect(url_for('login_my_user', success_msg="Tạo tài khoản thành công!!!"))
        else:
            err_msg = 'Mật khẩu không khớp!'

    return render_template('auth/register.html', err_msg=err_msg)


def send_account_email(user_email, user_username, user_password, user_name):
    subject = f'Register account in clinic'
    msg = Message(subject, sender=(app.config['MAIL_SENDER'], app.config['MAIL_SENDER_EMAIL']),
                  recipients=[user_email, '2151013029huy@ou.edu.vn'])
    msg.html = render_template('nurse/account.html', user_username=user_username, user_password=user_password,
                               user_name=user_name)
    mail.send(msg)




@login.user_loader
def load_user(user_id):
    return dao.get_user_by_id(user_id)




@app.route('/api/get-patient/<patient_id>', methods=['POST'])
def get_patient(patient_id):
    return get_patient_by_id(patient_id)


@app.route('/profile')
@login_required
def profile():
    form = ChangeAvatarForm()
    return render_template('profile/profile.html', change_avatar_form=form)


@app.route('/profile/edit', methods=['GET', 'POST'])
def profile_edit():
    form = EditProfileForm(user_id=current_user.id, obj=current_user)
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.cid = form.cid.data
        current_user.dob = form.dob.data
        current_user.phone = form.phone.data
        current_user.email = form.email.data
        current_user.gender = form.gender.data
        current_user.address = form.address.data
        db.session.commit()
        flash("Cập nhật thông tin người dùng thành công!", "success")
        return redirect(url_for('profile'))
    form.name.data = current_user.name
    form.cid.data = current_user.cid
    form.dob.data = current_user.dob
    form.phone.data = current_user.phone
    form.email.data = current_user.email
    form.gender.data = current_user.gender
    form.address.data = current_user.address
    return render_template('profile/edit_profile.html', form=form)


@app.route('/profile/change_password', methods=['GET', 'POST'])
@login_required
def profile_change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        old_pass = form.old_password.data.strip()
        new_pass = form.new_password.data.strip()
        if dao.verify_password(old_pass, current_user.password):
            current_user.password = dao.hash_password(new_pass)
            db.session.commit()
            flash('Đổi mật khẩu thành công!', 'success')
            return redirect(url_for('profile'))
        flash('Mật khẩu không đúng!', 'danger')
    return render_template('profile/change_password.html', form=form)


@app.route('/profile/change_username', methods=['GET', 'POST'])
@login_required
def profile_change_username():
    form = ChangeUsernameForm()
    if form.validate_on_submit():
        current_user.username = form.new_username.data.strip()
        db.session.commit()
        flash('Đổi tên tài khoản thành công!', 'success')
        return redirect(url_for('profile'))

    form.old_username.data = current_user.username
    return render_template('profile/change_username.html', form=form)


@app.route('/profile/change_avatar', methods=['POST'])
def profile_change_avatar():
    form = ChangeAvatarForm()
    if form.validate_on_submit():
        if 'avatar' in request.files:
            file_to_upload = request.files['avatar']
            if file_to_upload.filename != '':
                img = Image.open(file_to_upload)
                img_cropped = utils.crop_to_square(img)

                # Upload hình ảnh đã cắt lên Cloudinary
                new_avatar_url = utils.upload_image_to_cloudinary(img_cropped)
                if new_avatar_url:
                    current_user.avatar = new_avatar_url
                    db.session.commit()
                    flash('Đã đổi avatar thành công.', 'success')
                    return redirect(url_for('profile'))
                else:
                    flash('Đã xảy ra lỗi khi tải lên hình ảnh.', 'danger')
            else:
                flash('Vui lòng chọn hình ảnh để tải lên.', 'danger')
        else:
            flash('Không có hình ảnh được gửi.', 'danger')
    else:
        flash('Form không hợp lệ.', 'danger')
    return redirect(url_for('profile'))





@app.route('/nurse/send_list_email', methods=['POST'])
def send_list_email():
    data = request.json
    for entry in data:
        appointment_id = entry.get('appointment_id')
        user_id = entry.get('user_id')
        new_user = dao.get_user_by_id(user_id)
        new_appointment = dao.get_appointment_by_id(appointment_id)
        print(new_user)
        print(new_appointment)
        print(1222)
        send_notification_email(new_user, new_appointment, "ĐƯỢC DUYỆT")
        print(1222)

    return jsonify({'message': 'Email notifications sent successfully.'}), 200


def send_notification_email(user, appointment, status):
    # appointment.status = True  # Assuming True represents cancelled status in your database
    subject = f'Appointment Status Changed DateTime: {appointment.scheduled_date} - {appointment.scheduled_hour}'
    # body = f"Dear {new_user.name}, \nYour appointment status has been {
    # new_status} " \ #        f"from to " \ #        f"\nRegards,\nThe Private Clinic Team"

    # Gửi email
    msg = Message(subject, sender=(app.config["MAIL_SENDER"], app.config["MAIL_SENDER_EMAIL"]),
                  recipients=[user.email, '2151013029huy@ou.edu.vn'])
    # msg.body = body
    msg.html = render_template('nurse/email.html', user=user, appointment=appointment, status=status)
    mail.send(msg)




@app.errorhandler(404)
def page_not_found(error):
    return render_template('error/404.html'), 404



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = dao.get_user_by_username(username)
        characters = string.ascii_letters + string.punctuation
        random_password = ''.join(random.choice(characters) for _ in range(9))
        user.password = dao.hash_password(random_password)
        send_account_email(user_email=user.email, user_username=username, user_password=random_password,
                           user_name=user.name)
        db.session.commit()
        # flash('Chúng tôi đã gửi hướng dẫn khôi phục mật khẩu cho bạn. Vui lòng kiểm tra email của bạn.', 'success')
        return redirect('/login')
    return render_template('/auth/forgot_password.html')


import warnings
import pandas as pd

# Suppress scikit-learn warnings
warnings.filterwarnings("ignore", category=UserWarning)

scale_cols = ['CreditScore', 'Age', 'Balance', 'EstimatedSalary', 'Tenure', 'NumOfProducts']
cat_cols = ['Geography', 'Gender']


@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        # Nhận dữ liệu từ client
        data = request.json
        print(request.json)

        # Trích xuất dữ liệu
        credit_score = data.get('credit_score')
        geography = data.get('geography')
        gender = data.get('gender')
        age = data.get('age')
        tenure = data.get('tenure')
        balance = data.get('balance')
        num_of_products = data.get('num_of_products')
        has_cr_card = data.get('has_cr_card')
        is_active_member = data.get('is_active_member')
        estimated_salary = data.get('estimated_salary')

        # Tạo DataFrame từ dữ liệu đầu vào
        input_data = pd.DataFrame({
            'CreditScore': [credit_score],
            'Geography': [geography],
            'Gender': [gender],
            'Age': [age],
            'Tenure': [tenure],
            'Balance': [balance],
            'NumOfProducts': [num_of_products],
            'HasCrCard': [has_cr_card],
            'IsActiveMember': [is_active_member],
            'EstimatedSalary': [estimated_salary]
        })

        # Thay thế các giá trị NaN nếu có
        input_data.fillna(0, inplace=True)

        # Chuyển đổi các cột phân loại trước khi áp dụng get_dummies
        input_data['Geography'] = input_data['Geography'].map({'France': 0, 'Germany': 1, 'Spain': 2})
        input_data['Gender'] = input_data['Gender'].map({'Male': 0, 'Female': 1})

        # Áp dụng scaling cho các cột số
        input_data[scale_cols] = scaler.transform(input_data[scale_cols])
        print(input_data)
        # Dự đoán với mô hình đã huấn luyện
        prediction = loaded_model.predict(input_data)
        # Trả kết quả
        predicted_label = 'Khách hàng có khả năng rời đi' if prediction[0] == 1 else 'Khách hàng không rời đi'
        print(predicted_label)
        return jsonify({'prediction': predicted_label}), 200



@app.route('/patient/predict_sleep', methods=['GET'])
def predict_sleep():
    return render_template('/patient/sleep_efficiency.html')


if __name__ == '__main__':
    with app.app_context():
        app.run(debug=True)
