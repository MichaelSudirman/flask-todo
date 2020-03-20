from flask_sqlalchemy import SQLAlchemy 

# Initialize database to prevent circular dependency
db = SQLAlchemy()