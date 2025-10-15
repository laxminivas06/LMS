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
            "latitude": 17.272034,
            "longitude": 78.585136, # Replace with your college longitude
            'radius_km': 2.5  # 500 meter radius - adjust as needed
        }
    ]
    
    # Direct access keys
    ADMIN_DIRECT_ACCESS_KEY = 'ctrl_j_secret'
    USER_DIRECT_ACCESS_KEY = 'ctrl_k_secret'