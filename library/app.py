from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import json
import os
import pandas as pd
from math import radians, sin, cos, sqrt, atan2
from datetime import datetime, timedelta
from config import Config
from functools import wraps
from flask import send_file
import io
from io import BytesIO
import logging
import re

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

def require_location_verification(f):
    """Decorator to check location verification for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if location is verified
        if not session.get('location_verified'):
            return redirect(url_for('welcome'))
        
        # Check if session has expired
        if session.get('login_time'):
            try:
                login_time = datetime.fromisoformat(session.get('login_time'))
                if datetime.now() - login_time > timedelta(minutes=app.config['SESSION_TIMEOUT_MINUTES']):
                    session.clear()
                    flash('Session expired. Please verify your location again.', 'error')
                    return redirect(url_for('welcome'))
            except:
                session.clear()
                return redirect(url_for('welcome'))
        
        # For POST requests with location data, check current location
        if request.method == 'POST':
            # Handle both JSON and form data
            if request.is_json:
                data = request.get_json() or {}
            else:
                data = request.form
            
            if 'latitude' in data and 'longitude' in data:
                session['current_latitude'] = data['latitude']
                session['current_longitude'] = data['longitude']
                
                try:
                    user_lat = float(data['latitude'])
                    user_lon = float(data['longitude'])
                    allowed, location_name = is_location_allowed(user_lat, user_lon)
                    
                    if not allowed:
                        session.clear()
                        if request.is_json:
                            return jsonify({
                                'success': False, 
                                'message': 'You have moved outside the allowed boundary. Please verify your location again.',
                                'redirect': True,
                                'redirect_url': url_for('welcome')
                            })
                        else:
                            flash('You have moved outside the allowed boundary. Please verify your location again.', 'error')
                            return redirect(url_for('welcome'))
                except (TypeError, ValueError):
                    pass  # Ignore invalid location data
        
        return f(*args, **kwargs)
    
    return decorated_function

def load_json_data(filename):
    """Load JSON data from file with better error handling"""
    filepath = f'data/{filename}'
    try:
        # Create data directory if it doesn't exist
        os.makedirs('data', exist_ok=True)
        
        if not os.path.exists(filepath):
            logger.info(f"File {filepath} does not exist, returning empty list")
            return []
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                logger.info(f"File {filepath} is empty, returning empty list")
                return []
            data = json.loads(content)
            logger.info(f"Successfully loaded {len(data)} items from {filename}")
            return data
            
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in {filename}: {str(e)}")
        # Try to backup the corrupted file
        try:
            if os.path.exists(filepath):
                backup_path = f'{filepath}.corrupted.{datetime.now().strftime("%Y%m%d_%H%M%S")}'
                os.rename(filepath, backup_path)
                logger.info(f"Backed up corrupted file to {backup_path}")
        except:
            pass
        return []
    except Exception as e:
        logger.error(f"Error loading {filename}: {str(e)}")
        return []

def save_json_data(filename, data):
    """Save data to JSON file with better error handling"""
    filepath = f'data/{filename}'
    try:
        os.makedirs('data', exist_ok=True)
        
        # Create backup if file exists
        if os.path.exists(filepath):
            backup_path = f'{filepath}.backup.{datetime.now().strftime("%Y%m%d_%H%M%S")}'
            import shutil
            shutil.copy2(filepath, backup_path)
            logger.info(f"Created backup: {backup_path}")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Successfully saved {len(data)} items to {filename}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving to {filename}: {str(e)}")
        logger.error(traceback.format_exc())
        raise


def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates in kilometers"""
    R = 6371  # Earth's radius in km
    
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    
    return R * c

def is_location_allowed(user_lat, user_lon):
    """Check if user is within any allowed location with multiple boundary types"""
    boundaries = load_json_data('boundaries.json')
    
    for boundary in boundaries:
        if boundary['type'] == 'circle':
            # Convert radius_km to float to handle both string and number formats
            try:
                radius_km = float(boundary['radius_km'])
            except (ValueError, TypeError):
                logger.warning(f"Invalid radius_km value in boundary {boundary.get('name', 'unknown')}: {boundary.get('radius_km')}")
                continue
                
            distance = calculate_distance(
                user_lat, user_lon,
                boundary['latitude'], boundary['longitude']
            )
            if distance <= radius_km:
                return True, boundary['name']
        
        elif boundary['type'] == 'rectangle':
            # Check if point is within rectangle bounds
            if (boundary['south'] <= user_lat <= boundary['north'] and 
                boundary['west'] <= user_lon <= boundary['east']):
                return True, boundary['name']
        
        elif boundary['type'] == 'polygon':
            # Simple polygon point-in-polygon check
            if is_point_in_polygon(user_lat, user_lon, boundary['coordinates']):
                return True, boundary['name']
    
    return False, None

def is_point_in_polygon(lat, lon, polygon):
    """Check if a point is inside a polygon using ray casting algorithm"""
    n = len(polygon)
    inside = False
    
    j = n - 1
    for i in range(n):
        if (((polygon[i][1] > lon) != (polygon[j][1] > lon)) and
            (lat < (polygon[j][0] - polygon[i][0]) * (lon - polygon[i][1]) / 
             (polygon[j][1] - polygon[i][1]) + polygon[i][0])):
            inside = not inside
        j = i
    
    return inside


def validate_student_credentials(username, password):
    """Validate student credentials (rollno as username, DOB as password)"""
    users = load_json_data('users.json')
    user = next((u for u in users if u['username'] == username and u['role'] == 'student'), None)
    
    if user and user['password'] == password:
        return True, user
    return False, None

def validate_admin_credentials(username, password):
    """Validate admin credentials"""
    users = load_json_data('users.json')
    user = next((u for u in users if u['username'] == username and u['role'] == 'admin'), None)
    
    if user and user['password'] == password:
        return True, user
    return False, None

def is_valid_rollno(rollno):
    """Check if roll number is valid (alphanumeric, 10 characters)"""
    # Allow alphanumeric characters and exactly 10 characters
    return bool(re.match(r'^[A-Za-z0-9]{10}$', rollno))

def format_date(date_string):
    """Format date string for display"""
    try:
        if isinstance(date_string, str):
            return date_string[:10]  # Get YYYY-MM-DD part
        return "Unknown"
    except:
        return "Unknown"

def process_excel_users(file):
    """Process Excel file for bulk user upload"""
    try:
        df = pd.read_excel(file)
        required_columns = ['username', 'password', 'role', 'name']
        
        # Check if required columns exist
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return False, f"Missing columns: {', '.join(missing_columns)}"
        
        users = load_json_data('users.json')
        new_users = []
        errors = []
        
        for index, row in df.iterrows():
            username = str(row['username']).strip()
            password = str(row['password']).strip()
            role = str(row['role']).strip().lower()
            name = str(row['name']).strip()
            
            # Validate role
            if role not in ['admin', 'student']:
                errors.append(f"Row {index+2}: Invalid role '{role}'. Must be 'admin' or 'student'")
                continue
            
            # Validate student credentials
            if role == 'student':
                if not is_valid_rollno(username):
                    errors.append(f"Row {index+2}: Invalid roll number '{username}'. Must be exactly 10 alphanumeric characters")
                    continue
                
                # Remove any separators and validate DDMMYYYY format
                clean_password = ''.join(filter(str.isdigit, password))
                if not is_valid_dob(clean_password):
                    errors.append(f"Row {index+2}: Invalid date of birth '{password}'. Use DDMMYYYY format (8 digits)")
                    continue
                
                # Convert to ISO format for storage
                password = convert_to_iso_date(clean_password)
            
            # Check for duplicate username
            if any(user['username'] == username for user in users):
                errors.append(f"Row {index+2}: Username '{username}' already exists")
                continue
            
            new_user = {
                'id': len(users) + len(new_users) + 1,
                'username': username,
                'password': password,
                'role': role,
                'name': name,
                'created_at': datetime.now().isoformat(),
                'created_by': session.get('user_id', 'admin')
            }
            new_users.append(new_user)
        
        if errors:
            return False, ";\n".join(errors)
        
        # Add all new users
        users.extend(new_users)
        save_json_data('users.json', users)
        
        return True, f"Successfully added {len(new_users)} users"
        
    except Exception as e:
        logger.error(f"Error processing Excel file: {str(e)}")
        return False, f"Error processing Excel file: {str(e)}"

def process_excel_pdfs(file):
    """Process Excel file for bulk PDF upload"""
    try:
        df = pd.read_excel(file)
        required_columns = ['title', 'category', 'drive_link']
        
        # Check if required columns exist
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return False, f"Missing columns: {', '.join(missing_columns)}"
        
        pdfs = load_json_data('pdfs.json')
        new_pdfs = []
        errors = []
        
        for index, row in df.iterrows():
            title = str(row['title']).strip()
            category = str(row['category']).strip()
            drive_link = str(row['drive_link']).strip()
            
            # Basic validation
            if not title:
                errors.append(f"Row {index+2}: Title is required")
                continue
            
            if not category:
                errors.append(f"Row {index+2}: Category is required")
                continue
            
            if not drive_link.startswith(('http://', 'https://')):
                errors.append(f"Row {index+2}: Invalid drive link")
                continue
            
            # Process tags if provided
            tags = []
            if 'tags' in df.columns and pd.notna(row['tags']):
                tags = [tag.strip() for tag in str(row['tags']).split(',')]
            
            file_size = str(row['file_size']).strip() if 'file_size' in df.columns and pd.notna(row.get('file_size')) else 'N/A'
            
            new_pdf = {
                'id': len(pdfs) + len(new_pdfs) + 1,
                'title': title,
                'category': category,
                'tags': tags,
                'drive_link': drive_link,
                'file_size': file_size,
                'uploaded_by': session.get('user_id', 'admin'),
                'uploaded_at': datetime.now().isoformat(),
                'upload_date': datetime.now().strftime('%Y-%m-%d')
            }
            new_pdfs.append(new_pdf)
        
        if errors:
            return False, ";\n".join(errors)
        
        # Add all new PDFs
        pdfs.extend(new_pdfs)
        save_json_data('pdfs.json', pdfs)
        
        return True, f"Successfully added {len(new_pdfs)} PDFs"
        
    except Exception as e:
        logger.error(f"Error processing Excel file: {str(e)}")
        return False, f"Error processing Excel file: {str(e)}"

def is_valid_dob(dob):
    """Strict DOB validation (DDMMYYYY format - exactly 8 digits, no separators)"""
    try:
        # Check if it's exactly 8 digits and only digits
        if len(dob) != 8 or not dob.isdigit():
            return False
        
        # Extract day, month, year
        day = int(dob[:2])
        month = int(dob[2:4])
        year = int(dob[4:8])
        
        # Validate date ranges
        if month < 1 or month > 12:
            return False
        
        if day < 1 or day > 31:
            return False
        
        # Basic year validation (reasonable range)
        if year < 1900 or year > datetime.now().year:
            return False
        
        # Validate specific month-day combinations
        if month in [4, 6, 9, 11] and day > 30:
            return False
        
        # February validation
        if month == 2:
            # Leap year check
            if (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0):
                if day > 29:
                    return False
            else:
                if day > 28:
                    return False
        
        # Final validation using datetime
        datetime(year, month, day)
        return True
    except (ValueError, IndexError):
        return False

def convert_to_iso_date(dob_string):
    """Convert DDMMYYYY to ISO format (YYYY-MM-DD) for storage"""
    try:
        # Ensure it's exactly 8 digits
        if len(dob_string) == 8 and dob_string.isdigit():
            day = int(dob_string[:2])
            month = int(dob_string[2:4])
            year = int(dob_string[4:8])
            date_obj = datetime(year, month, day)
            return date_obj.strftime('%Y-%m-%d')
        return dob_string  # Return original if conversion fails
    except ValueError:
        return dob_string

@app.route('/check-boundary', methods=['POST'])
@require_location_verification
def check_boundary():
    """API endpoint to check if user is within allowed boundary"""
    if not session.get('location_verified'):
        return jsonify({
            'success': False,
            'message': 'Location not verified',
            'redirect': True,
            'redirect_url': url_for('welcome')
        }), 401
    
    data = request.get_json()
    user_lat = data.get('latitude')
    user_lon = data.get('longitude')
    
    if user_lat is None or user_lon is None:
        return jsonify({
            'success': False,
            'message': 'Location data required'
        }), 400
    
    try:
        user_lat = float(user_lat)
        user_lon = float(user_lon)
    except (TypeError, ValueError):
        return jsonify({
            'success': False,
            'message': 'Invalid location data'
        }), 400
    
    allowed, location_name = is_location_allowed(user_lat, user_lon)
    
    if not allowed:
        session.clear()
        logger.warning(f"User moved outside boundary: {user_lat}, {user_lon}")
        return jsonify({
            'success': False,
            'message': 'You have moved outside the allowed boundary. Please return to the designated area.',
            'redirect': True,
            'redirect_url': url_for('welcome')
        }), 403
    
    # Update session with current location
    session['current_latitude'] = user_lat
    session['current_longitude'] = user_lon
    session['last_location_check'] = datetime.now().isoformat()
    
    return jsonify({
        'success': True,
        'message': 'Location verified',
        'location': location_name
    })

@app.route('/login', methods=['GET', 'POST'])
@require_location_verification
def login():
    """Login page for admin and students - automatic role detection"""
    # Get direct access flags with proper defaults
    direct_admin = session.pop('direct_admin', False)
    direct_user = session.pop('direct_user', False)
    
    # Ensure they are boolean values
    direct_admin = bool(direct_admin)
    direct_user = bool(direct_user)
    
    if not session.get('location_verified'):
        return redirect(url_for('location_check'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill all fields', 'error')
            return render_template('login.html', 
                                 direct_admin=direct_admin, 
                                 direct_user=direct_user)
        
        # Try admin login first
        is_valid_admin, admin_user = validate_admin_credentials(username, password)
        if is_valid_admin and admin_user:
            session['user_id'] = admin_user['username']
            session['user_role'] = admin_user['role']
            session['login_time'] = datetime.now().isoformat()
            session.permanent = True
            
            logger.info(f"Admin logged in: {admin_user['username']}")
            flash(f'Welcome Administrator {admin_user["username"]}!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        # Try student login
        # Validate roll number format
        if is_valid_rollno(username):
            # Strict DOB validation - remove ANY non-digit characters
            clean_password = ''.join(filter(str.isdigit, password))
            
            # Check if original password contained special characters
            if any(not char.isdigit() for char in password):
                flash('Date of birth should contain only digits (DDMMYYYY format). No special characters or spaces allowed.', 'error')
                return render_template('login.html', 
                                     direct_admin=direct_admin, 
                                     direct_user=direct_user)
            
            # Validate DDMMYYYY format
            if not is_valid_dob(clean_password):
                flash('Invalid date of birth. Please use DDMMYYYY format (8 digits only). Example: 15082002 for 15th August 2002.', 'error')
                return render_template('login.html', 
                                     direct_admin=direct_admin, 
                                     direct_user=direct_user)
            
            # Convert to ISO format for checking against stored password
            iso_password = convert_to_iso_date(clean_password)
            
            # Validate with converted password
            is_valid_student, student_user = validate_student_credentials(username, iso_password)
            
            if is_valid_student and student_user:
                session['user_id'] = student_user['username']
                session['user_role'] = student_user['role']
                session['login_time'] = datetime.now().isoformat()
                session.permanent = True
                
                logger.info(f"Student logged in: {student_user['username']}")
                flash(f'Welcome {student_user["username"]}!', 'success')
                return redirect(url_for('dashboard'))
        
        # If neither worked
        logger.warning(f"Failed login attempt for username: {username}")
        flash('Invalid credentials or user not found', 'error')
    
    return render_template('login.html', 
                         direct_admin=direct_admin, 
                         direct_user=direct_user)
@app.route('/admin/add-user', methods=['POST'])
def add_user():
    """Add new user (Admin only)"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    data = request.get_json()
    
    required_fields = ['username', 'password', 'role', 'name']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
    
    if data['role'] == 'student':
        if not is_valid_rollno(data['username']):
            return jsonify({'success': False, 'message': 'Student username must be 10-digit alphanumeric roll number'}), 400
        
        # Remove any non-digit characters and validate
        clean_password = ''.join(filter(str.isdigit, data['password']))
        
        # Check if original contained special characters
        if any(not char.isdigit() for char in data['password']):
            return jsonify({'success': False, 'message': 'Student password should contain only digits (DDMMYYYY format). No special characters or spaces allowed.'}), 400
        
        if not is_valid_dob(clean_password):
            return jsonify({'success': False, 'message': 'Invalid date of birth format. Use DDMMYYYY (8 digits only, no separators)'}), 400
        
        # Convert to ISO format for storage
        data['password'] = convert_to_iso_date(clean_password)
    
    users = load_json_data('users.json')
    
    # Check if username already exists
    if any(user['username'] == data['username'] for user in users):
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    
    # Create new user
    new_user = {
        'id': len(users) + 1,
        'username': data['username'],
        'password': data['password'],
        'role': data['role'],
        'name': data['name'],
        'created_at': datetime.now().isoformat(),
        'created_by': session.get('user_id')
    }
    
    users.append(new_user)
    save_json_data('users.json', users)
    
    return jsonify({'success': True, 'message': 'User added successfully'})


@app.route('/location-check', methods=['GET', 'POST'])
def location_check():
    """Location verification endpoint"""
    if request.method == 'POST':
        data = request.get_json()
        user_lat = data.get('latitude')
        user_lon = data.get('longitude')
        
        if user_lat is None or user_lon is None:
            return jsonify({
                'success': False, 
                'message': 'Location data not provided.'
            })
        
        try:
            user_lat = float(user_lat)
            user_lon = float(user_lon)
        except (TypeError, ValueError):
            return jsonify({
                'success': False, 
                'message': 'Invalid location data.'
            })
        
        allowed, location_name = is_location_allowed(user_lat, user_lon)
        
        if allowed:
            session['location_verified'] = True
            session['verified_location'] = location_name
            session['location_timestamp'] = datetime.now().isoformat()
            session['current_latitude'] = user_lat
            session['current_longitude'] = user_lon
            logger.info(f"Location verified: {location_name}")
            return jsonify({
                'success': True, 
                'location': location_name,
                'redirect_url': url_for('login')
            })
        else:
            logger.warning(f"Location denied: {user_lat}, {user_lon}")
            return jsonify({
                'success': False, 
                'message': 'Access Denied: You are outside the allowed area.'
            })
    
    # For GET requests, check if location is already verified
    if session.get('location_verified'):
        return redirect(url_for('login'))
    
    return render_template('location_check.html')

@app.route('/')
def welcome():
    """Welcome page"""
    session.clear()
    logger.info("Welcome page accessed")
    
    # Load data for stats
    users = load_json_data('users.json')
    pdfs = load_json_data('pdfs.json')
    
    # Calculate statistics
    user_stats = {
        'total_users': len(users),
        'total_pdfs': len(pdfs),
        'total_categories': len(set(pdf['category'] for pdf in pdfs))
    }
    
    return render_template('welcome.html', user_stats=user_stats)


@app.route('/dashboard')
@require_location_verification
def dashboard():
    """PDF dashboard"""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    # Load data
    pdfs = load_json_data('pdfs.json')
    users = load_json_data('users.json')
    categories = list(set(pdf['category'] for pdf in pdfs))
    
    # Get current user profile
    current_user = next((u for u in users if u['username'] == session.get('user_id')), None)
    
    # Get search parameters
    search_query = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    
    # Filter PDFs
    filtered_pdfs = pdfs
    if search_query:
        filtered_pdfs = [pdf for pdf in filtered_pdfs 
                        if search_query.lower() in pdf['title'].lower() 
                        or any(search_query.lower() in tag.lower() for tag in pdf.get('tags', []))]
    
    if category_filter:
        filtered_pdfs = [pdf for pdf in filtered_pdfs if pdf['category'] == category_filter]
    
    # Get user statistics
    user_stats = {
        'total_users': len(users),
        'total_pdfs': len(pdfs),
        'total_categories': len(categories),
        'documents_viewed': session.get('documents_viewed', 0),
        'last_login': session.get('login_time', 'First time')[:10] if session.get('login_time') else 'First time'
    }
    
    return render_template('dashboard.html', 
                          pdfs=filtered_pdfs,
                          categories=categories,
                          search_query=search_query,
                          category_filter=category_filter,
                          username=session.get('user_id', 'user'),
                          user_role=session.get('user_role', 'user'),
                          location=session.get('verified_location'),
                          user_stats=user_stats,
                          user_profile=current_user)


import pandas as pd
import numpy as np
import time


def load_json_data_optimized(filename):
    """Optimized JSON data loading with lazy evaluation"""
    try:
        filepath = f'data/{filename}'
        if not os.path.exists(filepath):
            return []
        
        # For large files, consider streaming/chunking
        file_size = os.path.getsize(filepath)
        if file_size > 10 * 1024 * 1024:  # 10MB
            logger.warning(f"Large file detected: {filename} ({file_size} bytes)")
        
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Error loading {filename}: {str(e)}")
        return []


@app.route('/admin/location')
@require_location_verification
def admin_location():
    """Admin location boundary management page"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('admin_location.html',
                         username=session.get('user_id'),
                         location=session.get('verified_location'))


import traceback
import os

@app.route('/admin/save-boundary', methods=['POST'])
def save_boundary():
    """Save location boundary (Admin only)"""
    try:
        # Check admin permissions
        if session.get('user_role') != 'admin':
            logger.warning(f"Unauthorized access attempt by user: {session.get('user_id')}")
            return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'}), 403
        
        # Get and validate data
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        logger.info(f"Received boundary data: {data}")
        
        # Validate required fields
        required_fields = ['name', 'type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
        
        # Validate and convert data types
        if data['type'] == 'circle':
            circle_fields = ['latitude', 'longitude', 'radius_km']
            for field in circle_fields:
                if field not in data:
                    return jsonify({'success': False, 'message': f'Missing circle field: {field}'}), 400
                try:
                    # Convert to float to ensure proper data type
                    data[field] = float(data[field])
                except (ValueError, TypeError):
                    return jsonify({'success': False, 'message': f'Invalid {field} value: {data[field]}'}), 400
        
        elif data['type'] == 'rectangle':
            rect_fields = ['north', 'south', 'east', 'west']
            for field in rect_fields:
                if field not in data:
                    return jsonify({'success': False, 'message': f'Missing rectangle field: {field}'}), 400
                try:
                    # Convert to float
                    data[field] = float(data[field])
                except (ValueError, TypeError):
                    return jsonify({'success': False, 'message': f'Invalid {field} value: {data[field]}'}), 400
        
        elif data['type'] == 'polygon':
            if 'coordinates' not in data or not data['coordinates']:
                return jsonify({'success': False, 'message': 'Missing polygon coordinates'}), 400
            # Validate polygon coordinates
            try:
                for i, coord in enumerate(data['coordinates']):
                    if len(coord) != 2:
                        return jsonify({'success': False, 'message': f'Invalid coordinate at index {i}'}), 400
                    data['coordinates'][i] = [float(coord[0]), float(coord[1])]
            except (ValueError, TypeError) as e:
                return jsonify({'success': False, 'message': f'Invalid coordinate format: {str(e)}'}), 400
        
        else:
            return jsonify({'success': False, 'message': f'Invalid boundary type: {data["type"]}'}), 400
        
        # Load existing boundaries
        try:
            boundaries = load_json_data('boundaries.json')
        except Exception as e:
            logger.warning(f"Could not load boundaries, starting fresh: {str(e)}")
            boundaries = []
        
        # Check if boundary with same name exists
        existing_index = next((i for i, b in enumerate(boundaries) if b['name'] == data['name']), -1)
        
        if existing_index >= 0:
            # Update existing boundary
            boundaries[existing_index] = {
                **boundaries[existing_index],
                **data,
                'updated_at': datetime.now().isoformat(),
                'updated_by': session.get('user_id')
            }
            message = 'Boundary updated successfully'
            action = 'updated'
        else:
            # Add new boundary with ID
            new_boundary = {
                'id': len(boundaries) + 1,
                **data,
                'created_by': session.get('user_id'),
                'created_at': datetime.now().isoformat()
            }
            boundaries.append(new_boundary)
            message = 'Boundary saved successfully'
            action = 'created'
        
        # Save boundaries
        save_json_data('boundaries.json', boundaries)
        
        logger.info(f"Boundary '{data['name']}' {action} successfully. Total boundaries: {len(boundaries)}")
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        logger.error(f"Error saving boundary: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False, 
            'message': f'Server error while saving boundary: {str(e)}'
        }), 500


def fix_existing_boundaries():
    """Fix existing boundaries with string values"""
    try:
        boundaries = load_json_data('boundaries.json')
        fixed_count = 0
        
        for boundary in boundaries:
            if boundary['type'] == 'circle' and isinstance(boundary.get('radius_km'), str):
                try:
                    boundary['radius_km'] = float(boundary['radius_km'])
                    fixed_count += 1
                except (ValueError, TypeError):
                    logger.warning(f"Could not convert radius_km for boundary: {boundary.get('name')}")
        
        if fixed_count > 0:
            save_json_data('boundaries.json', boundaries)
            logger.info(f"Fixed {fixed_count} boundaries with string values")
        
        return fixed_count
    except Exception as e:
        logger.error(f"Error fixing boundaries: {str(e)}")
        return 0

# Call this function once to fix existing data
# fix_existing_boundaries()
#    
@app.route('/admin/get-boundaries')
def get_boundaries():
    """Get all location boundaries"""
    try:
        # Check admin permissions
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        boundaries = load_json_data('boundaries.json')
        logger.info(f"Loaded {len(boundaries)} boundaries")
        return jsonify({'success': True, 'boundaries': boundaries})
        
    except Exception as e:
        logger.error(f"Error loading boundaries: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False, 
            'message': f'Error loading boundaries: {str(e)}',
            'boundaries': []
        }), 500

@app.route('/admin/delete-boundary', methods=['POST'])
def delete_boundary():
    """Delete location boundary (Admin only)"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        data = request.get_json()
        boundary_name = data.get('name')
        
        if not boundary_name:
            return jsonify({'success': False, 'message': 'Boundary name required'}), 400
        
        boundaries = load_json_data('boundaries.json')
        initial_count = len(boundaries)
        boundaries = [b for b in boundaries if b['name'] != boundary_name]
        
        if len(boundaries) == initial_count:
            return jsonify({'success': False, 'message': 'Boundary not found'}), 404
        
        save_json_data('boundaries.json', boundaries)
        
        logger.info(f"Boundary '{boundary_name}' deleted successfully. Remaining boundaries: {len(boundaries)}")
        return jsonify({'success': True, 'message': 'Boundary deleted successfully'})
        
    except Exception as e:
        logger.error(f"Error deleting boundary: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False, 
            'message': f'Error deleting boundary: {str(e)}'
        }), 500
    

@app.route('/debug/boundaries')
def debug_boundaries():
    """Debug endpoint to check boundaries data"""
    try:
        boundaries = load_json_data('boundaries.json')
        return jsonify({
            'success': True,
            'boundaries': boundaries,
            'file_exists': os.path.exists('data/boundaries.json')
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        })

@app.route('/debug/save-test', methods=['POST'])
def debug_save_test():
    """Test endpoint to check if saving works"""
    try:
        data = request.get_json()
        logger.info(f"Received data: {data}")
        
        # Test saving simple data
        test_data = {
            'test': True,
            'timestamp': datetime.now().isoformat(),
            'received_data': data
        }
        
        # Save to a test file
        save_json_data('test.json', [test_data])
        
        return jsonify({
            'success': True,
            'message': 'Test save successful',
            'saved_data': test_data
        })
    except Exception as e:
        logger.error(f"Debug save error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500
    
def update_app_boundaries(boundaries):
    """Update app config with new boundaries"""
    try:
        # Convert boundaries to the format expected by is_location_allowed
        allowed_locations = []
        
        for boundary in boundaries:
            if boundary['type'] == 'circle':
                allowed_locations.append({
                    'name': boundary['name'],
                    'latitude': boundary['latitude'],
                    'longitude': boundary['longitude'],
                    'radius_km': float(boundary['radius_km'])
                })
            # For rectangle and polygon types, you might need additional logic
            # This is a simplified version focusing on circles
        
        app.config['ALLOWED_LOCATIONS'] = allowed_locations
        logger.info(f"Updated app boundaries with {len(allowed_locations)} locations")
        
    except Exception as e:
        logger.error(f"Error updating app boundaries: {str(e)}")
        
def save_json_data_optimized(filename, data):
    """Optimized JSON data saving with backup"""
    try:
        os.makedirs('data', exist_ok=True)
        filepath = f'data/{filename}'
        
        # Create backup for large files
        if os.path.exists(filepath) and os.path.getsize(filepath) > 5 * 1024 * 1024:
            backup_path = f'data/{filename}.backup.{datetime.now().strftime("%Y%m%d_%H%M%S")}'
            import shutil
            shutil.copy2(filepath, backup_path)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, separators=(',', ':'))  # Compact JSON
            
        logger.info(f"Successfully saved {len(data)} records to {filename}")
    except Exception as e:
        logger.error(f"Error saving data to {filename}: {str(e)}")
        raise

def process_excel_users_optimized(file):
    """Optimized bulk user upload with chunk processing"""
    try:
        # Read Excel in chunks for memory efficiency
        chunk_size = 1000
        chunks = pd.read_excel(file, chunksize=chunk_size)
        
        users = load_json_data('users.json')
        new_users = []
        errors = []
        processed_count = 0
        
        for chunk_idx, chunk in enumerate(chunks):
            # Process each chunk
            for index, row in chunk.iterrows():
                processed_count += 1
                
                # Show progress for large files
                if processed_count % 500 == 0:
                    logger.info(f"Processed {processed_count} users...")
                
                username = str(row['username']).strip()
                password = str(row['password']).strip()
                role = str(row['role']).strip().lower()
                name = str(row['name']).strip()
                
                # Validate role
                if role not in ['admin', 'student']:
                    errors.append(f"Row {chunk_idx * chunk_size + index + 2}: Invalid role '{role}'. Must be 'admin' or 'student'")
                    continue
                
                # Validate student credentials
                if role == 'student':
                    if not is_valid_rollno(username):
                        errors.append(f"Row {chunk_idx * chunk_size + index + 2}: Invalid roll number '{username}'. Must be exactly 10 alphanumeric characters")
                        continue
                    
                    # Remove any separators and validate DDMMYYYY format
                    clean_password = ''.join(filter(str.isdigit, password))
                    if not is_valid_dob(clean_password):
                        errors.append(f"Row {chunk_idx * chunk_size + index + 2}: Invalid date of birth '{password}'. Use DDMMYYYY format (8 digits)")
                        continue
                    
                    # Convert to ISO format for storage
                    password = convert_to_iso_date(clean_password)
                
                # Check for duplicate username
                if any(user['username'] == username for user in users) or \
                   any(user['username'] == username for user in new_users):
                    errors.append(f"Row {chunk_idx * chunk_size + index + 2}: Username '{username}' already exists")
                    continue
                
                new_user = {
                    'id': len(users) + len(new_users) + 1,
                    'username': username,
                    'password': password,
                    'role': role,
                    'name': name,
                    'created_at': datetime.now().isoformat(),
                    'created_by': session.get('user_id', 'admin')
                }
                new_users.append(new_user)
                
                # Save progress every 1000 records to prevent memory issues
                if len(new_users) % 1000 == 0:
                    users.extend(new_users)
                    save_json_data('users.json', users)
                    new_users = []  # Reset for next batch
                    logger.info(f"Saved batch of 1000 users...")
        
        # Add remaining new users
        if new_users:
            users.extend(new_users)
            save_json_data('users.json', users)
        
        if errors:
            return False, ";\n".join(errors[:100])  # Limit error output
        
        return True, f"Successfully added {processed_count} users"
        
    except Exception as e:
        logger.error(f"Error processing Excel file: {str(e)}")
        return False, f"Error processing Excel file: {str(e)}"

def process_excel_pdfs_optimized(file):
    """Optimized bulk PDF upload with chunk processing"""
    try:
        chunk_size = 1000
        chunks = pd.read_excel(file, chunksize=chunk_size)
        
        pdfs = load_json_data('pdfs.json')
        new_pdfs = []
        errors = []
        processed_count = 0
        
        for chunk_idx, chunk in enumerate(chunks):
            for index, row in chunk.iterrows():
                processed_count += 1
                
                # Progress tracking
                if processed_count % 500 == 0:
                    logger.info(f"Processed {processed_count} PDFs...")
                
                title = str(row['title']).strip()
                category = str(row['category']).strip()
                drive_link = str(row['drive_link']).strip()
                
                # Basic validation
                if not title:
                    errors.append(f"Row {chunk_idx * chunk_size + index + 2}: Title is required")
                    continue
                
                if not category:
                    errors.append(f"Row {chunk_idx * chunk_size + index + 2}: Category is required")
                    continue
                
                if not drive_link.startswith(('http://', 'https://')):
                    errors.append(f"Row {chunk_idx * chunk_size + index + 2}: Invalid drive link")
                    continue
                
                # Process tags if provided
                tags = []
                if 'tags' in chunk.columns and pd.notna(row['tags']):
                    tags = [tag.strip() for tag in str(row['tags']).split(',')]
                
                file_size = str(row['file_size']).strip() if 'file_size' in chunk.columns and pd.notna(row.get('file_size')) else 'N/A'
                
                new_pdf = {
                    'id': len(pdfs) + len(new_pdfs) + 1,
                    'title': title,
                    'category': category,
                    'tags': tags,
                    'drive_link': drive_link,
                    'file_size': file_size,
                    'uploaded_by': session.get('user_id', 'admin'),
                    'uploaded_at': datetime.now().isoformat(),
                    'upload_date': datetime.now().strftime('%Y-%m-%d')
                }
                new_pdfs.append(new_pdf)
                
                # Save progress every 1000 records
                if len(new_pdfs) % 1000 == 0:
                    pdfs.extend(new_pdfs)
                    save_json_data('pdfs.json', pdfs)
                    new_pdfs = []
                    logger.info(f"Saved batch of 1000 PDFs...")
        
        # Add remaining PDFs
        if new_pdfs:
            pdfs.extend(new_pdfs)
            save_json_data('pdfs.json', pdfs)
        
        if errors:
            return False, ";\n".join(errors[:100])
        
        return True, f"Successfully added {processed_count} PDFs"
        
    except Exception as e:
        logger.error(f"Error processing Excel file: {str(e)}")
        return False, f"Error processing Excel file: {str(e)}"
    
@app.route('/admin/delete-pdf/<int:pdf_id>', methods=['POST'])
@require_location_verification
def delete_pdf(pdf_id):
    """Delete PDF (Admin only)"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    pdfs = load_json_data('pdfs.json')
    pdfs = [pdf for pdf in pdfs if pdf['id'] != pdf_id]
    save_json_data('pdfs.json', pdfs)
    
    return jsonify({'success': True, 'message': 'PDF deleted successfully'})

# Update the admin dashboard route as well
@app.route('/admin')
@require_location_verification
def admin_dashboard():
    """Admin dashboard for managing PDFs and users"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    pdfs = load_json_data('pdfs.json')
    users = load_json_data('users.json')
    categories = list(set(pdf['category'] for pdf in pdfs))
    
    # Ensure all users have required fields
    for user in users:
        user.setdefault('created_at', 'Unknown')
        user.setdefault('name', 'Unknown')
    
    # Calculate statistics
    user_stats = {
        'total_users': len(users),
        'total_pdfs': len(pdfs),
        'total_categories': len(categories)
    }
    
    return render_template('admin_dashboard.html',
                         pdfs=pdfs,
                         users=users,
                         categories=categories,
                         username=session.get('user_id'),
                         location=session.get('verified_location'),
                         format_date=format_date,
                         user_stats=user_stats)

@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics"""
    try:
        users = load_json_data('users.json')
        pdfs = load_json_data('pdfs.json')
        
        stats = {
            'total_users': len(users),
            'total_pdfs': len(pdfs),
            'total_categories': len(set(pdf['category'] for pdf in pdfs)),
            'total_admins': len([user for user in users if user.get('role') == 'admin']),
            'total_students': len([user for user in users if user.get('role') == 'student'])
        }
        
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({'success': False, 'message': 'Error loading statistics'}), 500
    
@app.route('/admin/users')
@require_location_verification
def admin_users():
    """Admin users management page"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    users = load_json_data('users.json')
    
    # Ensure all users have required fields
    for user in users:
        user.setdefault('created_at', 'Unknown')
        user.setdefault('name', 'Unknown')
    
    return render_template('admin_users.html',
                         users=users,
                         username=session.get('user_id'),
                         location=session.get('verified_location'),
                         format_date=format_date)

@app.route('/admin/upload-users-excel', methods=['POST'])
@require_location_verification
def upload_users_excel():
    """Upload users via Excel file with progress tracking"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    if 'excel_file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
    
    file = request.files['excel_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith(('.xlsx', '.xls')):
        return jsonify({'success': False, 'message': 'Please upload an Excel file (.xlsx or .xls)'}), 400
    
    # Check file size (limit to 50MB for bulk uploads)
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if file_size > 50 * 1024 * 1024:  # 50MB
        return jsonify({'success': False, 'message': 'File size too large. Maximum 50MB allowed.'}), 400
    
    # Start processing
    start_time = time.time()
    success, message = process_excel_users_optimized(file)
    processing_time = time.time() - start_time
    
    logger.info(f"Bulk user upload completed in {processing_time:.2f} seconds")
    
    if success:
        return jsonify({
            'success': True, 
            'message': f"{message}. Processing time: {processing_time:.2f}s"
        })
    else:
        return jsonify({'success': False, 'message': message}), 400

@app.route('/admin/upload-pdfs-excel', methods=['POST'])
@require_location_verification
def upload_pdfs_excel():
    """Upload PDFs via Excel file with progress tracking"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    if 'excel_file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
    
    file = request.files['excel_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith(('.xlsx', '.xls')):
        return jsonify({'success': False, 'message': 'Please upload an Excel file (.xlsx or .xls)'}), 400
    
    # Check file size
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > 50 * 1024 * 1024:  # 50MB
        return jsonify({'success': False, 'message': 'File size too large. Maximum 50MB allowed.'}), 400
    
    # Start processing
    start_time = time.time()
    success, message = process_excel_pdfs_optimized(file)
    processing_time = time.time() - start_time
    
    logger.info(f"Bulk PDF upload completed in {processing_time:.2f} seconds")
    
    if success:
        return jsonify({
            'success': True, 
            'message': f"{message}. Processing time: {processing_time:.2f}s"
        })
    else:
        return jsonify({'success': False, 'message': message}), 400
    
@app.route('/admin/add-pdf', methods=['POST'])
@require_location_verification
def add_pdf():
    """Add new PDF (Admin only)"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    data = request.get_json()
    
    required_fields = ['title', 'category', 'drive_link']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
    
    pdfs = load_json_data('pdfs.json')
    
    # Create new PDF
    new_pdf = {
        'id': len(pdfs) + 1,
        'title': data['title'],
        'category': data['category'],
        'tags': data.get('tags', []),
        'drive_link': data['drive_link'],
        'file_size': data.get('file_size', 'N/A'),
        'uploaded_by': session.get('user_id'),
        'uploaded_at': datetime.now().isoformat(),
        'upload_date': datetime.now().strftime('%Y-%m-%d')
    }
    
    pdfs.append(new_pdf)
    save_json_data('pdfs.json', pdfs)
    
    return jsonify({'success': True, 'message': 'PDF added successfully'})

@app.route('/admin/delete-user/<username>', methods=['POST'])
@require_location_verification
def delete_user(username):
    """Delete user (Admin only)"""
    if session.get('user_role') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    users = load_json_data('users.json')
    users = [user for user in users if user['username'] != username]
    save_json_data('users.json', users)
    
    return jsonify({'success': True, 'message': 'User deleted successfully'})

@app.route('/logout')
def logout():
    """Logout endpoint"""
    session.clear()
    return redirect(url_for('welcome'))

@app.route('/api/pdfs')
@require_location_verification
def api_pdfs():
    """API endpoint for PDF data"""
    if not session.get('user_id'):
        return jsonify({'error': 'Authentication required'}), 401
    
    pdfs = load_json_data('pdfs.json')
    return jsonify(pdfs)

@app.route('/api/search-pdfs')
@require_location_verification
def api_search_pdfs():
    """API endpoint for searching PDFs"""
    if not session.get('user_id'):
        return jsonify({'error': 'Authentication required'}), 401
    
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    
    pdfs = load_json_data('pdfs.json')
    
    filtered_pdfs = pdfs
    if query:
        filtered_pdfs = [pdf for pdf in filtered_pdfs 
                        if query.lower() in pdf['title'].lower() 
                        or any(query.lower() in tag.lower() for tag in pdf.get('tags', []))]
    
    if category:
        filtered_pdfs = [pdf for pdf in filtered_pdfs if pdf['category'] == category]
    
    return jsonify(filtered_pdfs[:50])

@app.route('/admin-direct-access')
def admin_direct_access():
    """Special route for direct admin access via keyboard shortcut"""
    secret_key = request.args.get('key', '')
    
    if secret_key == app.config.get('ADMIN_DIRECT_ACCESS_KEY', 'ctrl_j_secret'):
        session['direct_admin'] = True
        session['direct_access_timestamp'] = datetime.now().isoformat()
        return redirect(url_for('login'))
    
    return redirect(url_for('login'))

@app.route('/admin/download-users-template')
@require_location_verification
def download_users_template():
    """Download Users template Excel file"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Create a DataFrame with user-specific columns
    df = pd.DataFrame(columns=['username', 'password', 'role', 'name'])
    
    # Add user-specific example rows with alphanumeric roll numbers
    examples = [
        {'username': '23N81A62B0', 'password': '15082002', 'role': 'student', 'name': 'Rajesh Kumar'},
        {'username': '22M91A12C5', 'password': '23112001', 'role': 'student', 'name': 'Priya Sharma'},
        {'username': 'admin2', 'password': 'securepassword123', 'role': 'admin', 'name': 'Library Manager'}
    ]
    
    # Append examples to the DataFrame
    df = pd.concat([df, pd.DataFrame(examples)], ignore_index=True)
    
    # Create a BytesIO buffer
    buffer = BytesIO()
    
    # Write DataFrame to Excel in the buffer
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Users Template', index=False)
    
    # Set the buffer's position to the beginning
    buffer.seek(0)
    
    # Return the file as an attachment
    return send_file(
        buffer,
        as_attachment=True,
        download_name='users_template.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/admin/download-pdfs-template')
@require_location_verification
def download_pdfs_template():
    """Download PDFs template Excel file"""
    if session.get('user_role') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Create a DataFrame with PDF-specific columns
    df = pd.DataFrame(columns=['title', 'category', 'drive_link', 'tags', 'file_size'])
    
    # Add PDF-specific example rows
    examples = [
        {
            'title': 'Advanced Python Programming', 
            'category': 'Programming', 
            'drive_link': 'https://drive.google.com/file/d/python_advanced_2023/view',
            'tags': 'python,advanced,programming',
            'file_size': '15.2 MB'
        },
        {
            'title': 'Machine Learning Fundamentals', 
            'category': 'Data Science', 
            'drive_link': 'https://drive.google.com/file/d/ml_fundamentals_2023/view',
            'tags': 'machine-learning,ai,data-science',
            'file_size': '8.7 MB'
        }
    ]
    
    # Append examples to the DataFrame
    df = pd.concat([df, pd.DataFrame(examples)], ignore_index=True)
    
    # Create a BytesIO buffer
    buffer = BytesIO()
    
    # Write DataFrame to Excel in the buffer
    with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='PDFs Template', index=False)
    
    # Set the buffer's position to the beginning
    buffer.seek(0)
    
    # Return the file as an attachment
    return send_file(
        buffer,
        as_attachment=True,
        download_name='pdfs_template.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/user-direct-access')
def user_direct_access():
    """Special route for direct user access via keyboard shortcut"""
    secret_key = request.args.get('key', '')
    
    if secret_key == app.config.get('USER_DIRECT_ACCESS_KEY', 'ctrl_k_secret'):
        session['direct_user'] = True
        session['direct_access_timestamp'] = datetime.now().isoformat()
        return redirect(url_for('login'))
    
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5001)