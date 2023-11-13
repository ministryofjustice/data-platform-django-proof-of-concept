# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


def init_app(app):
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data_access_manager.db"
    app.config[
        "SQLALCHEMY_TRACK_MODIFICATIONS"
    ] = False  # Optional: Disable event system if not needed
    db.init_app(app)

    with app.app_context():
        db.create_all()


class DataSource(db.Model):
    __tablename__ = "data_sources"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    aws_resource_arn = db.Column(
        db.String(255), unique=True
    )  # If applicable, ARN for the corresponding AWS resource
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    created_by = db.Column(db.String(255), db.ForeignKey("users.id"))
    aad_group_id = db.Column(db.String(255), unique=True)
    teams_id = db.Column(db.String(255), unique=True)

    # Relationships
    permissions = db.relationship(
        "UserDataSourcePermission", backref="data_source", lazy=True
    )
    user = db.relationship("User", backref="created_data_sources", lazy=True)

    def __repr__(self):
        return f"<DataSource {self.name}>"


class UserDataSourcePermission(db.Model):
    __tablename__ = "user_data_source_permissions"
    id = db.Column(db.Integer, primary_key=True)  # Auto-incrementing primary key
    user_id = db.Column(db.String(255), db.ForeignKey("users.id"), nullable=False)
    data_source_id = db.Column(
        db.Integer, db.ForeignKey("data_sources.id"), nullable=False
    )
    permission_type = db.Column(db.String(50))  # Could denote read, write, admin, etc.
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship("User", back_populates="permissions")

    def __repr__(self):
        return f"<UserDataSourcePermission {self.user_id} - {self.data_source_id}>"


# Assuming you will have a User model that might look something like this:
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(255), primary_key=True)  # Azure AD User Object ID
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    permissions = db.relationship("UserDataSourcePermission", back_populates="user")

    def __repr__(self):
        return f"<User {self.name}>"
