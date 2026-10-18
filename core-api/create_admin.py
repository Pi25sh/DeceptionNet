from database import SessionLocal, User

def create_admin():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == 'admin').first()
        if not user:
            user = User(username='admin', role='admin')
            user.set_password('deceptionnet')
            db.add(user)
            db.commit()
            print("Admin user created successfully.")
        else:
            print("Admin user already exists.")
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()
