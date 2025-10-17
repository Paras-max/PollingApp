from app import app, db, User

with app.app_context():
    admin_user = User.query.filter_by(username='admin').first()
    if admin_user:
        db.session.delete(admin_user)
        db.session.commit()
        print("Admin user removed successfully!")
    else:
        print("No admin user found.")
