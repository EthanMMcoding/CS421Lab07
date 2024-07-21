from main import db, app, User

with app.app_context():
    
    users = User.query.all()
    print(users)
    User.query.delete()
    db.session.commit()
    print(users)