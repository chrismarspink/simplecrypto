from flask_mail import Mail
from flask_mail import Message

msg = Message("test subject",sender="jkkim@test", recipients=['jkkim7202@gmail.com'])
msg.body ="hello flask_mail"
msg.html = "<b>HTML</b> body"
mail=Mail()
mail.send(msg)
