import DynamoDB as db
from werkzeug.security import generate_password_hash, check_password_hash


username = "aaaab"
password = "aaaab"
passwords = generate_password_hash(password)
db.put_item(username, passwords)
print(passwords)
print(db.get_item(username, "password", "S"))
print(check_password_hash(db.get_item(username, "password", "S"), password))
usernames = "gggg"
print(db.scan_table('user_name', 'S', usernames)[1])