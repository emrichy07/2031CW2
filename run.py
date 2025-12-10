import os
from dotenv import load_dotenv

# 1. Load the environment variables immediately
load_dotenv()

# 2. Now it is safe to import the app
from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'])