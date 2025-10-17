import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'

    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    SESSION_TIMEOUT_MINUTES = 60

    # Location configuration - UPDATE THESE WITH YOUR COLLEGE COORDINATES
    ALLOWED_LOCATIONS = [
        {
            'name': 'Sphoorthy Engineering College',
            "latitude": 17.282309,
            "longitude": 78.553238, # Replace with your college longitude
            'radius_km': 5000000  # 500 meter radius - adjust as needed
        }
    ]

    SESSION_TIMEOUT_MINUTES = 120
    
    # Upload settings
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max file size
    BULK_UPLOAD_CHUNK_SIZE = 1000
    
    # Admin access keys
    ADMIN_DIRECT_ACCESS_KEY = 'ctrl_j_secret'
    USER_DIRECT_ACCESS_KEY = 'ctrl_k_secret'
    
    # Performance settings
    JSONIFY_PRETTYPRINT_REGULAR = False