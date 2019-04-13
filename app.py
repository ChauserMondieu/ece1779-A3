from flask import Flask, render_template, redirect, url_for, request, session
from flask import flash, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash
import DynamoDB as db
import S3
import os

app = Flask(__name__)
ALLOWED_EXTENSIONS = ['png', 'jpg', 'JPG', 'PNG']
app.secret_key = '123456'


# tweak the file name uploaded
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


'''
# url authentication check
@app.before_request
def before_action():
    print(request.path)
    if not request.path=='/':
        if not 'username' in session:
            session['newurl']=request.path
            return redirect(url_for('login_page'))
'''


# the login page:the entrance of the whole program
@app.route('/', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        user_name = request.form['user_name']
        password = request.form['password']
        # determine the input is valid
        if user_name == "" or password == "":
            flash("Please enter your username or password")
            return render_template("Login_Page.html")
        else:
            # Login success - redirect to private page
            if db.scan_table('user_name', 'S', user_name)[1] != 0 \
                    and check_password_hash(db.get_item('People', 'user_name', user_name, "password", "S"), password):
                return redirect(url_for('private_page', user_name=user_name))
            # Login Fail
            elif db.scan_table('user_name', 'S', user_name)[1] == 0:
                flash("User name doesn't exist")
                return redirect(url_for('login_page'))
            elif check_password_hash(db.get_item(user_name, "password", "S"), password) == False:
                flash("Wrong password")
                return redirect(url_for('login_page'))
            else:
                flash("Unknown errors")
                return redirect(url_for('login_page'))
    else:
        flash("Hello")
        return render_template("Login_Page.html")


# the logout page:the main exist of the whole program
@app.route('/logout/<user_name>', methods=['GET', 'POST'])
def logout_page(user_name):
    flash("Successfully logged out of your page!")
    avatar_address = 'https://s3.amazonaws.com/ece1779avatar/People/' + str(user_name) + '.jpg'
    return render_template("Logout_Page_success.html",
                           user_name=user_name,
                           avatar_address=avatar_address)


# Show the register page of a new user
@app.route('/register_page', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        user_name = request.form['user_name']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        # Decide the username is invalid
        if user_name == "":
            flash("Please enter your username ", "ok")
            return render_template("Register_Page.html")
        else:
            # Decide the password is invalid
            if password == "":
                flash("Please enter your password", "ok")
                return render_template("Register_Page.html")
            else:
                # Decide the confirmed password is invalid
                if password_confirm == "":
                    flash("Please confirm your password", "ok")
                    return render_template("Register_Page.html")
                else:
                    # Username doesn't exist in the database
                    if db.scan_table('name', 'S', user_name)[1] == 0:
                        # Password and confirmed password match
                        if password == password_confirm:
                            password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
                            user_name = user_name
                            avatar_address = 'https://s3.amazonaws.com/ece1779avatar/People/' + str(user_name) + '.jpg'
                            # assign one default image for the user
                            S3.copy_photo('ece1779avatar', user_name, 'Public/default_avatar.jpg', 'People/')
                            S3.copy_photo('ece1779avatar', user_name, 'Public/default-background.jpg', 'Background/')
                            # Save the username & password to People table
                            db.put_item(table_name='People', key_name='user_name', key_value=user_name,
                                        attribute='password', attribute_type='S', attribute_value=password)
                            # Save the username & password to Space table
                            db.put_item(table_name='Space', key_name='user_name', key_value=user_name,
                                        attribute='messages', attribute_type='L', attribute_value=[])
                            default_memo=str("This is your private page "+user_name+" ,please enjoy!")
                            # Save the username & default memo to User table
                            db.put_item(table_name='User', key_name='user_name', key_value=user_name,
                                        attribute='memo', attribute_type='S', attribute_value=default_memo)
                            # Save the username & avatar address to Avatar table
                            db.put_item(table_name='Avatar', key_name='user_name', key_value=user_name,
                                        attribute='avatar', attribute_type='S', attribute_value=avatar_address)
                            flash('New account created successfully!', "ok")
                            return redirect(url_for('register_success_page', user_name=user_name))
                        # Password and confirmed password doesn't match
                        else:
                            flash('The password confirmation not pass!', "ok")
                            return redirect(url_for('register_page'))
                    # User name already exist
                    else:
                        flash('The user name already existed!', "ok")
                        return redirect(url_for('register_page'))
        # Nothing happened, return to the Register Page
    else:
        return render_template("Register_Page.html", method=request.method)


# Show to indicate that the register is successful
@app.route('/register_page/success/<user_name>')
def register_success_page(user_name):
    return render_template("Register_Page_success.html", user_name=user_name)


# Setting page which user could change their passwords and avatar
@app.route('/private/setting/<user_name>', methods=['GET', 'POST'])
def private_setting_page(user_name):
    avatar_address = 'https://s3.amazonaws.com/ece1779avatar/People/' + str(user_name) + '.jpg'
    background_address = 'https://s3.amazonaws.com/ece1779avatar/Background/' + str(user_name) + '.jpg'
    return render_template("Private_Setting_Page.html",
                           user_name=user_name,
                           avatar_address=avatar_address,
                           background_address=background_address)


# Setting the text-form processing page
@app.route('/text_change/<user_name>', methods=['GET', 'POST'])
def text_change(user_name):
    avatar_address = 'https://s3.amazonaws.com/ece1779avatar/People/' + str(user_name) + '.jpg'
    background_address = 'https://s3.amazonaws.com/ece1779avatar/Background/' + str(user_name) + '.jpg'
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    password_confirmation = request.form['password_confirm']
    if request.method == 'POST':
        # Decide the old password entered is not valid
        if old_password == "":
            flash("Please enter your old passwords", "one")
            return redirect(url_for('private_setting_page',
                                    user_name=user_name,
                                    avatar_address=avatar_address,
                                    background_address=background_address))
        else:
            # Decide the new password entered first time is not valid
            if new_password == "":
                flash("Please enter your new passwords", "one")
                return redirect(url_for('private_setting_page',
                                        user_name=user_name,
                                        avatar_address=avatar_address))
            else:
                # Decide the new password entered second time is not valid
                if password_confirmation == "":
                    flash("Please confirm your new passwords", "one")
                    return redirect(url_for('private_setting_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            background_address=background_address))
                else:
                    # Decide the old password entered does not match the stored one
                    if check_password_hash(db.get_item('People', 'user_name', user_name, "password", "S"),
                                           old_password) == False:
                        flash("Your old password is invalid, please type in again!", "one")
                        return redirect(url_for('private_setting_page',
                                                user_name=user_name,
                                                avatar_address=avatar_address,
                                                background_address=background_address))
                    else:
                        # Decide the new password entered in the second time does not match the first time
                        if new_password != password_confirmation:
                            flash(
                                "Your newpassword typed in second does not match the first time, please type in again!",
                                "one")
                            return redirect(url_for('private_setting_page',
                                                    user_name=user_name,
                                                    avatar_address=avatar_address,
                                                    background_address=background_address))
                        elif new_password == password_confirmation:
                            # Renew password stored in DynamoDB
                            db.put_item(table_name='People', key_name='user_name', key_value=user_name,
                                        attribute='password', attribute_type='S', attribute_value=new_password)
                            return redirect(url_for('private_setting_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            background_address=background_address))
                            # Unknown error
                        else:
                            flash("Unknown errors")
                            return redirect(url_for('private_setting_page',
                                                    user_name=user_name,
                                                    avatar_address=avatar_address,
                                                    background_address=background_address))
    return render_template("Private_Setting_Page.html",
                           user_name=user_name,
                           avatar_address=avatar_address,
                           background_address=background_address)


# Setting the image-form processing page
@app.route('/image_change/<user_name>', methods=['GET', 'POST'])
def image_change(user_name):
    avatar_address = 'https://s3.amazonaws.com/ece1779avatar/People/' + str(user_name) + '.jpg'
    background_address = 'https://s3.amazonaws.com/ece1779avatar/Background/' + str(user_name) + '.jpg'
    if request.method == 'POST':
        file_avatar = request.files["file_av"]
        file_background = request.files["file_bg"]
        if request.method == 'POST':
            # Decide the upload file is invalid
            if (file_avatar or allowed_file(file_avatar.filename)) == False:
                flash("Your avatar is invalid, please try again!", "two")
                return redirect(url_for('private_setting_page',
                                        user_name=user_name,
                                        avatar_address=avatar_address,
                                        background_address=background_address))
            # All requirement met
            else:
                if (file_background or allowed_file(file_background.filename)) == False:
                    # only renew the avatar stored in S3 bucket
                    base_path = os.path.dirname(__file__)
                    file_avatar.save(os.path.join(base_path, 'static/avatar.jpg'))
                    S3.upload_photo('People/',user_name)
                    # Save the username & avatar address to Avatar table
                    db.put_item(table_name='Avatar', key_name='user_name', key_value=user_name,
                                attribute='avatar', attribute_type='S', attribute_value=avatar_address)
                    flash("Only your avatar image is renewed", "two")
                    return redirect(url_for('private_setting_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            background_address=background_address))
                elif file_background and allowed_file(file_background.filename) :
                    # Renew the avatar and background stored in S3 bucket
                    base_path = os.path.dirname(__file__)
                    file_background.save(os.path.join(base_path, 'static/background.jpg'))
                    S3.upload_photo('Background/',user_name)
                    file_avatar.save(os.path.join(base_path, 'static/avatar.jpg'))
                    S3.upload_photo('People/', user_name)
                    return redirect(url_for('private_setting_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            background_address=background_address))
                # Unknown error
                else:
                    flash("Unknown errors", "two")
                    return redirect(url_for('private_setting_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            background_address=background_address))
    return render_template("Private_Setting_Page.html",
                           user_name=user_name,
                           avatar_address=avatar_address,
                           background_address=background_address)


# Setting the memo-form processing page
@app.route('/memo_change/<user_name>', methods=['GET', 'POST'])
def memo_change(user_name):
    avatar_address = 'https://s3.amazonaws.com/ece1779avatar/People/' + str(user_name) + '.jpg'
    background_address = 'https://s3.amazonaws.com/ece1779avatar/Background/' + str(user_name) + '.jpg'
    if request.method == 'POST':
        memo = request.form["memo"]
        if request.method == 'POST':
            # Decide the upload file is invalid
            if memo=="":
                flash("please enter your memo", "three")
                return redirect(url_for('private_setting_page',
                                        user_name=user_name,
                                        avatar_address=avatar_address,
                                        background_address=background_address))
            # All requirement met
            else:
                if memo != "":
                    # the reqirements are met
                    flash("memo uploaded successfully!", "three")
                    # Renew memo stored in DynamoDB
                    db.put_item(table_name='User', key_name='user_name', key_value=user_name,
                                attribute='memo', attribute_type='S', attribute_value=memo)
                    return redirect(url_for('private_setting_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            background_address=background_address))
                # Unknown error
                else:
                    flash("Unknown errors", "three")
                    return redirect(url_for('private_setting_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            background_address=background_address))
    return render_template("Private_Setting_Page.html",
                           user_name=user_name,
                           avatar_address=avatar_address,
                           background_address=background_address)


@app.route('/alluser/<user_name>', methods=['GET', 'POST'])
def private_all_user_page(user_name):
    avatar_address = 'https://s3.amazonaws.com/ece1779avatar/People/' + str(user_name) + '.jpg'
    background_address = 'https://s3.amazonaws.com/ece1779avatar/Background/' + str(user_name) + '.jpg'
    messages = db.get_all_items(table_name="People",attribute_name="user_name")
    memo_list=[]
    avatar_list=[]
    for name_memo in messages:
        memo_list.append(db.get_item('User', 'user_name', name_memo, "memo", "S"))
        avatar_list.append(db.get_item('Avatar', 'user_name', name_memo, "avatar", "S"))
    return render_template("Private_User_Page.html",
                           user_name=user_name,
                           messages=messages,
                           memo_list=memo_list,
                           avatar_list=avatar_list,
                           avatar_address=avatar_address,
                           background_address=background_address)


# Show the private page of each user
@app.route('/private/<user_name>', methods=['GET', 'POST'])
def private_page(user_name):
    avatar_address = 'https://s3.amazonaws.com/ece1779avatar/People/' + str(user_name) + '.jpg'
    background_address = 'https://s3.amazonaws.com/ece1779avatar/Background/' + str(user_name) + '.jpg'
    memo = db.get_item(table_name='User', key_name='user_name', key_value=user_name,
                           attribute='memo', attribute_type='S')
    messages = db.get_item(table_name='Space', key_name='user_name', key_value=user_name,
                           attribute='messages', attribute_type='L')
    if request.method == 'POST':
        private_message = request.form['private_message']
        private_receiver = request.form['private_receiver']
        sender_name = str(user_name)
        item = []
        # The message input is not valid
        if private_message == "":
            flash("Please enter your message!")
            return redirect(url_for('private_page',
                                    user_name=user_name,
                                    avatar_address=avatar_address,
                                    messages=messages,
                                    memo=memo,
                                    background_address=background_address))
        else:
            # the message input is valid while the receiver input is not valid
            if private_receiver == "":
                flash("Please enter one valid receiver!")
                return redirect(url_for('private_page',
                                        user_name=user_name,
                                        avatar_address=avatar_address,
                                        messages=messages,
                                        memo=memo,
                                        background_address=background_address))
            else:
                # the message input and receiver input is valid while the receiver is unexist
                if db.scan_table('user_name', 'S', sender_name)[1] == 0:
                    flash("The sender's name does not exist!")
                    return redirect(url_for('private_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            messages=messages,
                                            memo=memo,
                                            background_address=background_address))
                # the inputs are valid
                elif private_message != "" and private_receiver != "" \
                        and db.scan_table('user_name', 'S', sender_name)[1] != 0:
                    sender_avatar=db.get_item('Avatar', 'user_name', sender_name, "avatar", "S")
                    item.append(sender_name)
                    item.append(private_message)
                    item.append(sender_avatar)
                    add_item = {'SS': item}
                    messages.append(add_item)
                    db.put_item(table_name='Space', key_name='user_name', key_value=str(private_receiver),
                                attribute='messages', attribute_type='L', attribute_value=messages)
                    return redirect(url_for('private_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            messages=messages,
                                            memo=memo,
                                            background_address=background_address))
                # Unknown error occurred
                else:
                    flash("Unknown error")
                    return redirect(url_for('private_page',
                                            user_name=user_name,
                                            avatar_address=avatar_address,
                                            messages=messages,
                                            memo=memo,
                                            background_address=background_address))

    else:
        return render_template("Private_Page.html",
                               user_name=user_name,
                               messages=messages,
                               memo=memo,
                               avatar_address=avatar_address)


@app.route('/public/<user_name>', methods=['GET', 'POST'])
def public_page(user_name):
    avatar_address = 'https://s3.amazonaws.com/ece1779avatar/People/' + str(user_name) + '.jpg'
    background_address = 'https://s3.amazonaws.com/ece1779avatar/Background/' + str(user_name) + '.jpg'
    messages = db.get_item(table_name='Group', key_name='group_name', key_value='public',
                           attribute='messages', attribute_type='L')
    if request.method == 'POST':
        public_message = request.form['public_message']
        sender_name = str(user_name)
        item = []
        # the message input is valid
        if public_message == "":
            flash("Please enter your message!")
            return redirect(url_for('public_page',
                                    user_name=user_name,
                                    avatar_address=avatar_address,
                                    messages=messages,
                                    background_address=background_address))
        # all requirement met
        elif public_message != "":
            item.append(sender_name)
            item.append(public_message)
            item.append(db.get_item('Avatar', 'user_name', sender_name, "avatar", "S"))
            add_item = {'SS': item}
            messages.append(add_item)
            db.put_item(table_name='Group', key_name='group_name', key_value='public',
                        attribute='messages', attribute_type='L', attribute_value=messages)
            return redirect(url_for('public_page',
                                    user_name=user_name,
                                    avatar_address=avatar_address,
                                    messages=messages,
                                    background_address=background_address))
        # Unknown errors
        else:
            flash("Unmknown error!")
            return redirect(url_for('public_page',
                                    user_name=user_name,
                                    avatar_address=avatar_address,
                                    messages=messages,
                                    background_address=background_address))
    else:
        return render_template("Public_Page.html",
                               user_name=user_name,
                               avatar_address=avatar_address,
                               messages=messages,
                               background_address=background_address)


if __name__ == '__main__':
    app.run()
