from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from database import *
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from datetime import datetime
import os
import logging
from functools import wraps
from logging.handlers import RotatingFileHandler
import sys

# Настройка логирования для Windows
def setup_logging():
    """Настройка логирования для Windows"""
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    
    file_handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3, encoding='utf-8')
    file_handler.setFormatter(formatter)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    logging.basicConfig(
        level=logging.INFO,
        handlers=[file_handler, console_handler]
    )

setup_logging()
logger = logging.getLogger(__name__)

# Создаем экземпляр приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# Инициализация Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите в систему для доступа к этой странице.'
login_manager.login_message_category = 'info'

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

# Декораторы для валидации
def validate_required_fields(required_fields):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method == 'POST':
                missing_fields = [field for field in required_fields if not request.form.get(field)]
                if missing_fields:
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({
                            'success': False, 
                            'error': f'Отсутствуют обязательные поля: {", ".join(missing_fields)}'
                        })
                    else:
                        flash(f'Отсутствуют обязательные поля: {", ".join(missing_fields)}', 'error')
                        return redirect(request.referrer or url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'manager':
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': 'Недостаточно прав'})
            else:
                flash('У вас нет прав для выполнения этой операции', 'error')
                return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Добавляем функцию now в контекст всех шаблонов
@app.context_processor
def utility_processor():
    return dict(now=datetime.now)

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = get_user_by_id(user_id)
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['role'])
        return None
    except Exception as e:
        logger.error(f"Error loading user: {e}")
        return None

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Пожалуйста, заполните все поля', 'error')
            return render_template('login.html')
        
        try:
            user_data = get_user_by_username(username)
            
            if user_data and user_data['is_active'] and check_password_hash(user_data['password_hash'], password):
                user = User(user_data['id'], user_data['username'], user_data['role'])
                login_user(user, remember=True)
                logger.info(f"User {username} logged in successfully")
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            elif user_data and not user_data['is_active']:
                flash('Учетная запись отключена', 'error')
                logger.warning(f"Attempt to login to disabled account: {username}")
            else:
                flash('Неверное имя пользователя или пароль', 'error')
                logger.warning(f"Failed login attempt for username: {username}")
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Произошла ошибка при входе в систему', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user_requests = get_user_requests(current_user.id)
        all_requests = get_all_requests()
        remote_requests = [r for r in all_requests if r['request_type'] == 'remote']
        onsite_requests = [r for r in all_requests if r['request_type'] == 'on_site']
        
        documents = get_documents_by_user(current_user.id)
        equipment = get_equipment_by_user(current_user.id)
        employees = get_employees()
        
        all_requests_sorted = sorted(all_requests, key=lambda x: x.get('created_at', ''), reverse=True)
        
        return render_template('dashboard.html', 
                             user=current_user,
                             user_requests=user_requests,
                             all_requests=all_requests_sorted,
                             remote_requests=remote_requests,
                             onsite_requests=onsite_requests,
                             documents=documents,
                             equipment=equipment,
                             employees=employees)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Ошибка при загрузке данных', 'error')
        return render_template('dashboard.html', 
                             user=current_user,
                             user_requests=[],
                             all_requests=[],
                             remote_requests=[],
                             onsite_requests=[],
                             documents=[],
                             equipment=[],
                             employees=[])

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash('Вы успешно вышли из системы', 'success')
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))

# Раздел 1: Заявки
@app.route('/requests')
@login_required
def requests_page():
    request_type = request.args.get('type', 'all')
    assigned_filter = request.args.get('assigned', 'all')
    organization_filter = request.args.get('organization', 'all')
    show_completed = request.args.get('show_completed', 'false') == 'true'
    
    if request_type == 'remote':
        requests = get_requests_by_type('remote')
    elif request_type == 'on_site':
        requests = get_requests_by_type('on_site')
    else:
        requests = get_all_requests()
    
    if assigned_filter == 'assigned':
        requests = [r for r in requests if r['assigned_username']]
    elif assigned_filter == 'unassigned':
        requests = [r for r in requests if not r['assigned_username']]
    elif assigned_filter == 'my':
        requests = [r for r in requests if r['assigned_to'] == current_user.id]
    
    if organization_filter != 'all':
        requests = [r for r in requests if r['client_organization'] == organization_filter]
    
    if not show_completed:
        requests = [r for r in requests if r['status'] != 'completed']
    
    employees = get_employees()
    organizations = get_organizations()
    
    return render_template('requests.html', 
                         requests=requests, 
                         request_type=request_type,
                         assigned_filter=assigned_filter,
                         organization_filter=organization_filter,
                         show_completed=show_completed,
                         user=current_user,
                         employees=employees,
                         organizations=organizations)

@app.route('/create_request', methods=['POST'])
@login_required
@manager_required
@validate_required_fields(['title', 'client_name', 'client_phone', 'client_organization'])
def create_request_route():
    try:
        title = request.form['title']
        description = request.form.get('description', '')
        request_type = request.form['request_type']
        assigned_to = request.form.get('assigned_to', '0')
        deadline = request.form.get('deadline', '')
        client_name = request.form['client_name']
        client_phone = request.form['client_phone']
        client_organization = request.form['client_organization']
        client_address = request.form.get('client_address', '')
        priority = request.form.get('priority', 'medium')
        
        if assigned_to == '0' or assigned_to == '':
            assigned_to = None
        
        request_id = create_request(title, description, request_type, assigned_to, deadline, 
                      current_user.id, client_name, client_phone, client_organization, client_address, priority)
        
        if request_id:
            flash('Заявка создана успешно', 'success')
            logger.info(f"Request created: {title} by {current_user.username}")
        else:
            flash('Ошибка при создании заявки', 'error')
        
    except Exception as e:
        logger.error(f"Error creating request: {e}")
        flash('Ошибка при создании заявки', 'error')
    
    return redirect(url_for('requests_page'))

@app.route('/take_request/<int:request_id>', methods=['POST'])
@login_required
def take_request_route(request_id):
    db = None
    try:
        db = get_db()
        request_data = db.execute(
            'SELECT * FROM requests WHERE id = ? AND (assigned_to IS NULL OR assigned_to = 0)',
            (request_id,)
        ).fetchone()
        
        if request_data:
            db.execute(
                'UPDATE requests SET assigned_to = ? WHERE id = ?',
                (current_user.id, request_id)
            )
            db.commit()
            flash('Заявка успешно взята в работу', 'success')
            logger.info(f"Request {request_id} taken by {current_user.username}")
        else:
            flash('Заявка уже назначена другому сотруднику', 'error')
            
    except Exception as e:
        logger.error(f"Error taking request: {e}")
        flash('Ошибка при взятии заявки', 'error')
    finally:
        if db:
            db.close()
    
    return redirect(url_for('requests_page'))

@app.route('/update_request_status/<int:request_id>', methods=['POST'])
@login_required
def update_request_status_route(request_id):
    try:
        status = request.form.get('status')
        
        if not status:
            flash('Статус не указан', 'error')
            return redirect(url_for('requests_page'))
        
        if current_user.role != 'manager':
            db = get_db()
            request_data = db.execute(
                'SELECT assigned_to FROM requests WHERE id = ?', (request_id,)
            ).fetchone()
            db.close()
            
            if not request_data:
                flash('Заявка не найдена', 'error')
                return redirect(url_for('requests_page'))
                
            if request_data['assigned_to'] != current_user.id:
                flash('У вас нет прав для изменения этой заявки', 'error')
                return redirect(url_for('requests_page'))
        
        update_request_status(request_id, status)
        flash('Статус заявки обновлен', 'success')
        logger.info(f"Request {request_id} status updated to {status} by {current_user.username}")
        
    except Exception as e:
        logger.error(f"Error updating request status: {e}")
        flash('Ошибка при обновлении статуса', 'error')
    
    return redirect(url_for('requests_page'))

@app.route('/assign_request/<int:request_id>', methods=['POST'])
@login_required
@manager_required
def assign_request_route(request_id):
    try:
        assigned_to = request.form['assigned_to']
        if assigned_to and assigned_to != '0':
            assign_request_to_user(request_id, assigned_to)
            flash('Заявка успешно назначена', 'success')
            logger.info(f"Request {request_id} assigned to user {assigned_to} by {current_user.username}")
        else:
            flash('Выберите сотрудника для назначения', 'error')
            
    except Exception as e:
        logger.error(f"Error assigning request: {e}")
        flash('Ошибка при назначении заявки', 'error')
    
    return redirect(url_for('requests_page'))

@app.route('/edit_request_full/<int:request_id>', methods=['POST'])
@login_required
@manager_required
@validate_required_fields(['title', 'client_name', 'client_phone', 'client_organization'])
def edit_request_full_route(request_id):
    try:
        update_data = {
            'title': request.form.get('title'),
            'description': request.form.get('description', ''),
            'request_type': request.form.get('request_type'),
            'status': request.form.get('status'),
            'priority': request.form.get('priority'),
            'assigned_to': request.form.get('assigned_to'),
            'deadline': request.form.get('deadline'),
            'client_name': request.form.get('client_name'),
            'client_phone': request.form.get('client_phone'),
            'client_organization': request.form.get('client_organization'),
            'client_address': request.form.get('client_address', '')
        }
        
        if update_data['assigned_to'] == '0' or update_data['assigned_to'] == '':
            update_data['assigned_to'] = None
        
        update_data = {k: v for k, v in update_data.items() if v is not None}
        
        success = update_request(request_id, update_data)
        
        if success:
            logger.info(f"Request {request_id} edited by {current_user.username}")
            return jsonify({'success': True, 'message': 'Изменения сохранены успешно'})
        else:
            return jsonify({'success': False, 'error': 'Ошибка при обновлении заявки'})
        
    except Exception as e:
        logger.error(f"Error editing request: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Раздел 2: Документы
@app.route('/documents')
@login_required
def documents_page():
    try:
        document_type = request.args.get('type', 'all')
        show_sent = request.args.get('show_sent', 'false') == 'true'
        
        if document_type == 'act':
            documents = get_documents_by_user(current_user.id, 'act')
        elif document_type == 'invoice':
            documents = get_documents_by_user(current_user.id, 'invoice')
        else:
            documents = get_documents_by_user(current_user.id)
        
        if not show_sent:
            documents = [doc for doc in documents if doc['status'] == 'draft']
        
        organizations = get_organizations_from_documents(current_user.id)
        
        return render_template('documents.html', 
                             documents=documents,
                             document_type=document_type,
                             show_sent=show_sent,
                             organizations=organizations,
                             user=current_user,
                             now=datetime.now)
    except Exception as e:
        logger.error(f"Documents page error: {e}")
        flash('Ошибка при загрузке документов', 'error')
        return render_template('documents.html', 
                             documents=[],
                             document_type='all',
                             organizations=[],
                             user=current_user,
                             now=datetime.now)

def generate_document_number(document_type):
    prefix = 'СЧ' if document_type == 'invoice' else 'АКТ'
    now = datetime.now()
    date_part = now.strftime('%Y%m%d')
    time_part = now.strftime('%H%M%S')
    return f"{prefix}-{date_part}-{time_part}"

@app.route('/create_document', methods=['POST'])
@login_required
@validate_required_fields(['document_type', 'amount', 'client_name', 'client_organization', 'client_phone'])
def create_document_route():
    try:
        document_type = request.form['document_type']
        document_number = generate_document_number(document_type)
        document_date = datetime.now().strftime('%Y-%m-%d')
        amount = float(request.form['amount'])
        client_name = request.form['client_name']
        client_organization = request.form['client_organization']
        client_phone = request.form['client_phone']
        
        client_email = request.form.get('client_email', '')
        client_address = request.form.get('client_address', '')
        description = request.form.get('description', '')
        
        document_id = create_document(
            document_type=document_type,
            document_number=document_number,
            request_id=None,
            client_name=client_name,
            client_organization=client_organization,
            client_phone=client_phone,
            client_email=client_email,
            client_address=client_address,
            amount=amount,
            created_by=current_user.id,
            document_date=document_date,
            description=description
        )
        
        if document_id:
            flash(f'Документ {document_number} успешно создан', 'success')
            logger.info(f"Document {document_number} created by {current_user.username}")
        else:
            flash('Ошибка при создании документа', 'error')
            
    except ValueError as e:
        flash('Некорректная сумма', 'error')
    except Exception as e:
        logger.error(f"Error creating document: {e}")
        flash('Ошибка при создании документа', 'error')
    
    return redirect(url_for('documents_page'))

@app.route('/update_document_status/<int:document_id>', methods=['POST'])
@login_required
@manager_required
def update_document_status_route(document_id):
    try:
        status = request.form['status']
        
        if status not in ['draft', 'sent']:
            flash('Неверный статус документа', 'error')
            return redirect(url_for('documents_page'))
        
        update_document_status(document_id, status)
        flash('Статус документа обновлен', 'success')
        logger.info(f"Document {document_id} status updated to {status} by {current_user.username}")
    except Exception as e:
        logger.error(f"Error updating document status: {e}")
        flash('Ошибка при обновлении статуса', 'error')
    
    return redirect(url_for('documents_page'))

@app.route('/edit_document_full/<int:document_id>', methods=['POST'])
@login_required
@manager_required
@validate_required_fields(['client_name', 'client_organization', 'client_phone', 'amount'])
def edit_document_full_route(document_id):
    try:
        client_name = request.form.get('client_name')
        client_organization = request.form.get('client_organization')
        client_phone = request.form.get('client_phone')
        client_email = request.form.get('client_email', '')
        client_address = request.form.get('client_address', '')
        amount = request.form.get('amount')
        description = request.form.get('description', '')
        status = request.form.get('status')
        
        with db_connection() as db:
            db.execute('''
                UPDATE documents 
                SET client_name = ?, client_organization = ?, client_phone = ?, 
                    client_email = ?, client_address = ?, amount = ?, description = ?, status = ?
                WHERE id = ?
            ''', (client_name, client_organization, client_phone, client_email, 
                  client_address, amount, description, status, document_id))
        
        logger.info(f"Document {document_id} edited by {current_user.username}")
        return jsonify({'success': True, 'message': 'Изменения сохранены успешно'})
        
    except Exception as e:
        logger.error(f"Error editing document: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_document/<int:document_id>', methods=['POST'])
@login_required
@manager_required
def delete_document_route(document_id):
    try:
        with db_connection() as db:
            document = db.execute(
                'SELECT document_number FROM documents WHERE id = ?', (document_id,)
            ).fetchone()
            
            db.execute('DELETE FROM documents WHERE id = ?', (document_id,))
        
        if document:
            flash(f'Документ {document["document_number"]} успешно удален', 'success')
            logger.info(f"Document {document['document_number']} deleted by {current_user.username}")
        else:
            flash('Документ успешно удален', 'success')
            
    except Exception as e:
        logger.error(f"Error deleting document: {e}")
        flash('Ошибка при удалении документа', 'error')
    
    return redirect(url_for('documents_page'))

# Раздел 3: Оборудование
@app.route('/equipment')
@login_required
def equipment_page():
    try:
        show_removed = request.args.get('show_removed', 'false') == 'true'
        
        equipment = get_all_equipment() if current_user.role == 'manager' else get_equipment_by_user(current_user.id)
        
        if not show_removed:
            equipment = [item for item in equipment if item['status'] != 'removed']
        
        return render_template('equipment.html', 
                             equipment=equipment, 
                             user=current_user)
                             
    except Exception as e:
        logger.error(f"Equipment page error: {e}")
        flash('Ошибка при загрузке оборудования', 'error')
        equipment = get_all_equipment() if current_user.role == 'manager' else get_equipment_by_user(current_user.id)
        return render_template('equipment.html', 
                             equipment=equipment, 
                             user=current_user)

@app.route('/create_equipment', methods=['POST'])
@login_required
@validate_required_fields(['equipment_name', 'installation_date', 'client_name', 'client_address'])
def create_equipment_route():
    try:
        equipment_name = request.form['equipment_name']
        serial_number = request.form.get('serial_number', '')
        installation_date = request.form['installation_date']
        client_name = request.form['client_name']
        client_address = request.form['client_address']
        status = request.form.get('status', 'installed')
        notes = request.form.get('notes', '')
        
        request_id = None
        warranty_until = ''
        specifications = ''
        
        equipment_id = create_equipment(request_id, equipment_name, serial_number, 
                        installation_date, current_user.id, client_name, client_address, 
                        status, warranty_until, specifications, notes)
        
        if equipment_id:
            flash('Оборудование добавлено успешно', 'success')
            logger.info(f"Equipment {equipment_name} created by {current_user.username}")
        else:
            flash('Ошибка при добавлении оборудования', 'error')
        
    except Exception as e:
        logger.error(f"Error creating equipment: {e}")
        flash('Ошибка при добавлении оборудования', 'error')
    
    return redirect(url_for('equipment_page'))

@app.route('/update_equipment_status/<int:equipment_id>', methods=['POST'])
@login_required
@manager_required
def update_equipment_status_route(equipment_id):
    try:
        status = request.form['status']
        
        if status not in ['installed', 'removed']:
            flash('Неверный статус оборудования', 'error')
            return redirect(url_for('equipment_page'))
        
        with db_connection() as db:
            db.execute(
                'UPDATE equipment SET status = ? WHERE id = ?',
                (status, equipment_id)
            )
        
        flash('Статус оборудования обновлен', 'success')
        logger.info(f"Equipment {equipment_id} status updated to {status} by {current_user.username}")
    except Exception as e:
        logger.error(f"Error updating equipment status: {e}")
        flash('Ошибка при обновлении статуса', 'error')
    
    return redirect(url_for('equipment_page'))

@app.route('/edit_equipment_full/<int:equipment_id>', methods=['POST'])
@login_required
@manager_required
@validate_required_fields(['equipment_name', 'installation_date', 'client_name', 'client_address'])
def edit_equipment_full_route(equipment_id):
    try:
        update_data = {
            'equipment_name': request.form.get('equipment_name'),
            'serial_number': request.form.get('serial_number', ''),
            'installation_date': request.form.get('installation_date'),
            'client_name': request.form.get('client_name'),
            'client_address': request.form.get('client_address'),
            'status': request.form.get('status'),
            'notes': request.form.get('notes', '')
        }
        
        update_data = {k: v for k, v in update_data.items() if v is not None}
        
        success = update_equipment(equipment_id, update_data)
        
        if success:
            logger.info(f"Equipment {equipment_id} edited by {current_user.username}")
            return jsonify({'success': True, 'message': 'Изменения сохранены успешно'})
        else:
            return jsonify({'success': False, 'error': 'Ошибка при обновлении оборудования'})
        
    except Exception as e:
        logger.error(f"Error editing equipment: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_equipment/<int:equipment_id>', methods=['POST'])
@login_required
@manager_required
def delete_equipment_route(equipment_id):
    try:
        with db_connection() as db:
            equipment = db.execute(
                'SELECT equipment_name FROM equipment WHERE id = ?', (equipment_id,)
            ).fetchone()
            
            db.execute('DELETE FROM equipment WHERE id = ?', (equipment_id,))
        
        if equipment:
            flash(f'Оборудование "{equipment["equipment_name"]}" успешно удалено', 'success')
            logger.info(f"Equipment {equipment['equipment_name']} deleted by {current_user.username}")
        else:
            flash('Оборудование успешно удален', 'success')
            
    except Exception as e:
        logger.error(f"Error deleting equipment: {e}")
        flash('Ошибка при удалении оборудования', 'error')
    
    return redirect(url_for('equipment_page'))

# Раздел 4: Пользователи
@app.route('/users')
@login_required
@manager_required
def users_page():
    try:
        show_inactive = request.args.get('show_inactive', 'false') == 'true'
        
        if show_inactive:
            users = get_all_users_with_status()
        else:
            users = get_active_users()
        
        users_with_stats = []
        for user in users:
            stats = get_user_stats(user['id'])
            users_with_stats.append({
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'created_at': user['created_at'],
                'is_active': user['is_active'],
                'stats': stats
            })
        
        return render_template('users.html', 
                             users=users_with_stats,
                             show_inactive=show_inactive,
                             user=current_user)
                             
    except Exception as e:
        logger.error(f"Users page error: {e}")
        flash('Ошибка при загрузке пользователей', 'error')
        return render_template('users.html', 
                             users=[],
                             show_inactive=False,
                             user=current_user)

@app.route('/create_user', methods=['POST'])
@login_required
@manager_required
@validate_required_fields(['username', 'password', 'role'])
def create_user_route():
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'employee')
        
        if len(password) < 4:
            return jsonify({'success': False, 'error': 'Пароль должен содержать минимум 4 символа'})
        
        success = create_user(username, password, role)
        
        if success:
            logger.info(f"User {username} created by {current_user.username}")
            return jsonify({'success': True, 'message': f'Пользователь {username} успешно создан'})
        else:
            return jsonify({'success': False, 'error': 'Пользователь с таким именем уже существует'})
        
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/update_user_role/<int:user_id>', methods=['POST'])
@login_required
@manager_required
def update_user_role_route(user_id):
    try:
        new_role = request.form.get('role')
        
        if not new_role or new_role not in ['manager', 'employee']:
            return jsonify({'success': False, 'error': 'Неверная роль'})
        
        if user_id == current_user.id:
            return jsonify({'success': False, 'error': 'Нельзя изменить свою собственную роль'})
        
        success = update_user_role(user_id, new_role)
        
        if success:
            logger.info(f"User {user_id} role updated to {new_role} by {current_user.username}")
            return jsonify({'success': True, 'message': 'Роль пользователя обновлена'})
        else:
            return jsonify({'success': False, 'error': 'Ошибка при обновлении роли'})
        
    except Exception as e:
        logger.error(f"Error updating user role: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/update_user_status/<int:user_id>', methods=['POST'])
@login_required
@manager_required
def update_user_status_route(user_id):
    try:
        is_active = request.form.get('is_active')
        
        if is_active is None:
            return jsonify({'success': False, 'error': 'Статус не указан'})
        
        is_active = int(is_active)
        
        if user_id == current_user.id and is_active == 0:
            return jsonify({'success': False, 'error': 'Нельзя отключить свою собственную учетную запись'})
        
        success = update_user_status(user_id, is_active)
        
        if success:
            status_text = 'активен' if is_active else 'отключен'
            logger.info(f"User {user_id} status updated to {status_text} by {current_user.username}")
            return jsonify({'success': True, 'message': f'Пользователь теперь {status_text}'})
        else:
            return jsonify({'success': False, 'error': 'Ошибка при обновлении статуса'})
        
    except Exception as e:
        logger.error(f"Error updating user status: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@manager_required
def delete_user_route(user_id):
    try:
        if user_id == current_user.id:
            return jsonify({'success': False, 'error': 'Нельзя удалить свою собственную учетную запись'})
        
        success, message = delete_user(user_id)
        
        if success:
            logger.info(f"User {user_id} deleted by {current_user.username}")
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message})
        
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/reset_user_password/<int:user_id>', methods=['POST'])
@login_required
@manager_required
@validate_required_fields(['new_password'])
def reset_user_password_route(user_id):
    try:
        new_password = request.form.get('new_password', '').strip()
        
        if len(new_password) < 4:
            return jsonify({'success': False, 'error': 'Пароль должен содержать минимум 4 символа'})
        
        with db_connection() as db:
            password_hash = generate_password_hash(new_password)
            
            db.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (password_hash, user_id)
            )
        
        logger.info(f"User {user_id} password reset by {current_user.username}")
        return jsonify({'success': True, 'message': 'Пароль успешно сброшен'})
        
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        return jsonify({'success': False, 'error': str(e)})

# Раздел 5: Организации
@app.route('/organizations')
@login_required
def organizations_page():
    try:
        search_query = request.args.get('search', '')
        
        if search_query:
            organizations = search_organizations(search_query)
        else:
            organizations = get_all_organizations()
        
        return render_template('organizations.html', 
                             organizations=organizations,
                             search_query=search_query,
                             user=current_user)
                             
    except Exception as e:
        logger.error(f"Organizations page error: {e}")
        flash('Ошибка при загрузке организаций', 'error')
        return render_template('organizations.html', 
                             organizations=[],
                             search_query='',
                             user=current_user)

# НОВЫЙ ИСПРАВЛЕННЫЙ МАРШРУТ
@app.route('/create_organization', methods=['POST'])
@login_required
def create_organization_route():
    """Создать новую организацию"""
    try:
        unp = request.form.get('unp', '').strip()
        short_name = request.form.get('short_name', '').strip()
        legal_address = request.form.get('legal_address', '')
        actual_address = request.form.get('actual_address', '')
        phone = request.form.get('phone', '')
        email = request.form.get('email', '')
        director = request.form.get('director', '')
        
        # Проверка обязательных полей
        if not unp or not short_name:
            return jsonify({'success': False, 'error': 'УНП и название организации обязательны'})
        
        if len(unp) != 9 or not unp.isdigit():
            return jsonify({'success': False, 'error': 'УНП должен содержать 9 цифр'})

        # Создаем организацию через обновленную функцию
        result = create_organization(
            unp=unp,
            short_name=short_name,
            legal_address=legal_address,
            actual_address=actual_address,
            phone=phone,
            email=email,
            director=director,
            created_by=current_user.id
        )
        
        if result['success']:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': result['error']})
            
    except Exception as e:
        logger.error(f"Error creating organization: {e}")
        return jsonify({'success': False, 'error': 'Ошибка сервера при создании организации'})

@app.route('/edit_organization_full/<int:org_id>', methods=['POST'])
@login_required
def edit_organization_full_route(org_id):
    """Редактирование организации"""
    try:
        short_name = request.form.get('short_name')
        legal_address = request.form.get('legal_address', '')
        actual_address = request.form.get('actual_address', '')
        phone = request.form.get('phone', '')
        email = request.form.get('email', '')
        director = request.form.get('director', '')
        
        # Проверка обязательных полей
        if not short_name:
            return jsonify({'success': False, 'error': 'Название организации обязательно'})
        
        # Подготавливаем данные для обновления
        update_data = {
            'short_name': short_name,
            'legal_address': legal_address,
            'actual_address': actual_address,
            'phone': phone,
            'email': email,
            'director': director
        }
        
        # Убираем пустые значения
        update_data = {k: v for k, v in update_data.items() if v is not None}
        
        success = update_organization(org_id, update_data)
        
        if success:
            logger.info(f"Organization {org_id} edited by {current_user.username}")
            return jsonify({'success': True, 'message': 'Изменения сохранены успешно'})
        else:
            return jsonify({'success': False, 'error': 'Ошибка при обновлении организации'})
            
    except Exception as e:
        logger.error(f"Error editing organization: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_organization/<int:org_id>', methods=['POST'])
@login_required
@manager_required
def delete_organization_route(org_id):
    """Удаление организации"""
    try:
        success, message = delete_organization(org_id)
        
        if success:
            logger.info(f"Organization {org_id} deleted by {current_user.username}")
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message})
            
    except Exception as e:
        logger.error(f"Error deleting organization: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_organizations_json')
@login_required
def get_organizations_json_route():
    """Получить организации в формате JSON для выпадающих списков"""
    try:
        organizations = get_organizations_for_select()
        return jsonify(organizations)
    except Exception as e:
        logger.error(f"Error getting organizations JSON: {e}")
        return jsonify([])

# Обработчики ошибок
@app.errorhandler(404)
def not_found_error(error):
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    flash('Внутренняя ошибка сервера', 'error')
    return redirect(url_for('dashboard'))

def setup_database():
    """Инициализация базы данных и создание тестовых пользователей"""
    logger.info("Инициализация базы данных...")
    
    try:
        init_db()
        
        # Создаем тестовых пользователей
        test_users = [
            ('admin', 'admin123', 'manager'),
            ('tech1', 'tech123', 'employee'),
            ('tech2', 'tech123', 'employee'),
            ('manager1', 'mgr123', 'manager')
        ]
        
        for username, password, role in test_users:
            existing_user = get_user_by_username(username)
            if not existing_user:
                create_user(username, password, role)
                logger.info(f"Создан пользователь: {username} ({role})")
            else:
                logger.info(f"Пользователь уже существует: {username}")
        
        logger.info("База данных инициализирована успешно!")
        print("\nТЕСТОВЫЕ ПОЛЬЗОВАТЕЛИ:")
        print("   Менеджер: admin / admin123")
        print("   Сотрудник: tech1 / tech123")
        print("   Сотрудник: tech2 / tech123")
        print("   Менеджер: manager1 / mgr123")
        
    except Exception as e:
        logger.error(f"Ошибка инициализации: {e}")

if __name__ == '__main__':
    setup_database()
    app.run(host='0.0.0.0', port=5000, debug=True)