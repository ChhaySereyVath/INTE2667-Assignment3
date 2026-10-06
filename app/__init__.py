from app.security.pii_filter import init_pii_filter

def create_app():
    app = Flask(__name__)

    app.config.update(...)

    # Initialise extensions
    db.init_app(app)
    init_pii_filter(app)    # ← add this line
    JWTManager(app)
    CORS(app, supports_credentials=True)