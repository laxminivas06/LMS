import os

class Config:
    # Security settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    
    # Allow all locations for testing
    ALLOWED_LOCATIONS = [
        {
            'name': 'Global Access',
            'latitude': 17.272034,
            'longitude': 78.585136,
            'radius_km': 100000.0  # Very large radius to allow all locations
        }
    ]
    
    # App settings
    SESSION_TIMEOUT_MINUTES = 120  # Longer session for convenience
    PERMANENT_SESSION_LIFETIME = 7200