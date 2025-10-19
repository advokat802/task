import sqlite3
import os
import logging
from werkzeug.security import generate_password_hash
from datetime import datetime
from contextlib import contextmanager

# Настройка логирования
logger = logging.getLogger(__name__)

DATABASE = 'task_manager.db'

def get_db():
    """Получить соединение с базой данных"""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

@contextmanager
def db_connection():
    """Контекстный менеджер для работы с БД"""
    db = None
    try:
        db = get_db()
        yield db
        db.commit()
    except Exception as e:
        if db:
            db.rollback()
        logger.error(f"Database error: {e}")
        raise e
    finally:
        if db:
            db.close()

def init_db():
    """Инициализировать базу данных и создать таблицы"""
    with db_connection() as db:
        # Создание таблицы пользователей
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('manager', 'employee')),
                is_active BOOLEAN DEFAULT 1 CHECK(is_active IN (0, 1)),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Создание таблицы заявок
        db.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                request_type TEXT NOT NULL CHECK(request_type IN ('remote', 'on_site')),
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'in_progress', 'completed')),
                priority TEXT DEFAULT 'medium' CHECK(priority IN ('low', 'medium', 'high')),
                assigned_to INTEGER,
                deadline TIMESTAMP,
                created_by INTEGER NOT NULL,
                client_name TEXT NOT NULL,
                client_phone TEXT NOT NULL,
                client_organization TEXT NOT NULL,
                client_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (assigned_to) REFERENCES users (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')
        
        # Создание таблицы документов (акты и счета)
        db.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_type TEXT NOT NULL CHECK(document_type IN ('act', 'invoice')),
                document_number TEXT NOT NULL,
                request_id INTEGER,
                client_name TEXT NOT NULL,
                client_organization TEXT,
                client_phone TEXT NOT NULL,
                client_email TEXT,
                client_address TEXT,
                amount DECIMAL(10,2) NOT NULL,
                created_by INTEGER NOT NULL,
                document_date DATE NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'draft' CHECK(status IN ('draft', 'sent')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (request_id) REFERENCES requests (id),
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')
        
        # Создание таблицы оборудования
        db.execute('''
            CREATE TABLE IF NOT EXISTS equipment (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER,
                equipment_name TEXT NOT NULL,
                serial_number TEXT,
                installation_date DATE NOT NULL,
                installed_by INTEGER NOT NULL,
                client_name TEXT NOT NULL,
                client_address TEXT NOT NULL,
                status TEXT DEFAULT 'installed' CHECK(status IN ('installed', 'removed')),
                warranty_until DATE,
                specifications TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (request_id) REFERENCES requests (id),
                FOREIGN KEY (installed_by) REFERENCES users (id)
            )
        ''')
        
        # Создание таблицы организаций
        db.execute('''
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                unp TEXT UNIQUE NOT NULL,
                short_name TEXT NOT NULL,
                legal_address TEXT,
                actual_address TEXT,
                phone TEXT,
                email TEXT,
                director TEXT,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')
        
        # Создание индексов для улучшения производительности
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status)',
            'CREATE INDEX IF NOT EXISTS idx_requests_type ON requests(request_type)',
            'CREATE INDEX IF NOT EXISTS idx_requests_assigned ON requests(assigned_to)',
            'CREATE INDEX IF NOT EXISTS idx_requests_organization ON requests(client_organization)',
            'CREATE INDEX IF NOT EXISTS idx_requests_deadline ON requests(deadline)',
            'CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type)',
            'CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)',
            'CREATE INDEX IF NOT EXISTS idx_equipment_status ON equipment(status)',
            'CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)',
            'CREATE INDEX IF NOT EXISTS idx_organizations_unp ON organizations(unp)',
            'CREATE INDEX IF NOT EXISTS idx_organizations_short_name ON organizations(short_name)',
            'CREATE INDEX IF NOT EXISTS idx_organizations_created_by ON organizations(created_by)'
        ]
        
        for index_sql in indexes:
            db.execute(index_sql)

def test_database():
    """Тест соединения с базой данных"""
    try:
        with db_connection() as db:
            result = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            print("📊 Таблицы в базе:", [row['name'] for row in result])
            
            # Проверим таблицу organizations
            orgs = db.execute("SELECT * FROM organizations").fetchall()
            print("📋 Организации в базе:", len(orgs))
            return True
    except Exception as e:
        print(f"❌ Ошибка базы данных: {e}")
        return False

# Функции для работы с организациями
def create_organization(unp, short_name, legal_address, actual_address, phone, email, director, created_by):
    """Создать новую организацию"""
    try:
        print(f"🛢️  DATABASE: Creating organization with UNP: {unp}")
        print(f"🛢️  DATABASE: Short name: {short_name}")
        
        with db_connection() as db:
            # Проверяем существование организации
            existing = db.execute(
                'SELECT id, short_name FROM organizations WHERE unp = ?', (unp,)
            ).fetchone()
            
            if existing:
                print(f"🛢️  DATABASE: Organization with UNP {unp} already exists (ID: {existing['id']}, Name: {existing['short_name']})")
                return None
            
            print(f"🛢️  DATABASE: UNP {unp} is available, creating organization...")
            
            # Пробуем вставить новую организацию
            cursor = db.execute(
                '''INSERT INTO organizations 
                (unp, short_name, legal_address, actual_address, phone, email, director, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (unp, short_name, legal_address, actual_address, phone, email, director, created_by)
            )
            org_id = cursor.lastrowid
            print(f"🛢️  DATABASE: Organization created with ID: {org_id}")
            return org_id
            
    except sqlite3.IntegrityError as e:
        print(f"🛢️  DATABASE: Integrity error (UNIQUE constraint failed): {e}")
        print(f"🛢️  DATABASE: This means UNP {unp} already exists in database")
        return None
    except Exception as e:
        print(f"🛢️  DATABASE: Unexpected error creating organization: {e}")
        import traceback
        traceback.print_exc()
        return None

def get_organization_by_unp(unp):
    """Получить организацию по УНП"""
    try:
        with db_connection() as db:
            organization = db.execute(
                'SELECT * FROM organizations WHERE unp = ?', (unp,)
            ).fetchone()
            return dict(organization) if organization else None
    except Exception as e:
        logger.error(f"Error getting organization by UNP: {e}")
        return None

def get_organization_by_id(org_id):
    """Получить организацию по ID"""
    try:
        with db_connection() as db:
            organization = db.execute(
                'SELECT o.*, u.username as created_by_username FROM organizations o LEFT JOIN users u ON o.created_by = u.id WHERE o.id = ?', (org_id,)
            ).fetchone()
            return dict(organization) if organization else None
    except Exception as e:
        logger.error(f"Error getting organization by ID: {e}")
        return None

def get_all_organizations():
    """Получить все организации"""
    try:
        with db_connection() as db:
            organizations = db.execute('''
                SELECT o.*, u.username as created_by_username 
                FROM organizations o 
                LEFT JOIN users u ON o.created_by = u.id 
                ORDER BY o.short_name
            ''').fetchall()
            return [dict(org) for org in organizations]
    except Exception as e:
        logger.error(f"Error getting all organizations: {e}")
        return []

def search_organizations(query):
    """Поиск организаций"""
    try:
        with db_connection() as db:
            search_pattern = f'%{query}%'
            organizations = db.execute('''
                SELECT o.*, u.username as created_by_username 
                FROM organizations o 
                LEFT JOIN users u ON o.created_by = u.id 
                WHERE o.unp LIKE ? OR o.short_name LIKE ? 
                OR o.legal_address LIKE ? OR o.director LIKE ?
                ORDER BY o.short_name
            ''', (search_pattern, search_pattern, search_pattern, search_pattern)).fetchall()
            return [dict(org) for org in organizations]
    except Exception as e:
        logger.error(f"Error searching organizations: {e}")
        return []

def update_organization(org_id, update_data):
    """Обновить данные организации"""
    try:
        with db_connection() as db:
            set_clause = ', '.join([f"{key} = ?" for key in update_data.keys()])
            values = list(update_data.values())
            values.append(org_id)
            
            query = f'UPDATE organizations SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
            db.execute(query, values)
            return True
    except Exception as e:
        logger.error(f"Error updating organization: {e}")
        return False

def delete_organization(org_id):
    """Удалить организацию"""
    try:
        with db_connection() as db:
            # Проверяем, используется ли организация в заявках
            used_in_requests = db.execute(
                'SELECT COUNT(*) as count FROM requests WHERE client_organization = (SELECT short_name FROM organizations WHERE id = ?)',
                (org_id,)
            ).fetchone()
            
            if used_in_requests['count'] > 0:
                return False, 'Организация используется в заявках и не может быть удалена'
            
            db.execute('DELETE FROM organizations WHERE id = ?', (org_id,))
            return True, 'Организация успешно удалена'
    except Exception as e:
        logger.error(f"Error deleting organization: {e}")
        return False, str(e)

def get_organizations_for_select():
    """Получить организации для выпадающих списков"""
    try:
        with db_connection() as db:
            organizations = db.execute(
                'SELECT id, short_name, unp FROM organizations ORDER BY short_name'
            ).fetchall()
            return [dict(org) for org in organizations]
    except Exception as e:
        logger.error(f"Error getting organizations for select: {e}")
        return []

# Существующие функции (оставляем без изменений)
def create_user(username, password, role):
    """Создать нового пользователя"""
    try:
        with db_connection() as db:
            password_hash = generate_password_hash(password)
            db.execute(
                'INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, 1)',
                (username, password_hash, role)
            )
            return True
    except sqlite3.IntegrityError:
        return False
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return False

def get_user_by_username(username):
    """Получить пользователя по имени"""
    try:
        with db_connection() as db:
            user = db.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()
            return dict(user) if user else None
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        return None

def get_user_by_id(user_id):
    """Получить пользователя по ID"""
    try:
        with db_connection() as db:
            user = db.execute(
                'SELECT * FROM users WHERE id = ?', (user_id,)
            ).fetchone()
            return dict(user) if user else None
    except Exception as e:
        logger.error(f"Error getting user by id: {e}")
        return None

def get_employees():
    """Получить список всех активных пользователей"""
    try:
        with db_connection() as db:
            employees = db.execute(
                'SELECT id, username, role FROM users WHERE is_active = 1 ORDER BY username'
            ).fetchall()
            return [dict(emp) for emp in employees]
    except Exception as e:
        logger.error(f"Error getting employees: {e}")
        return []

# Функции для работы с заявками
def create_request(title, description, request_type, assigned_to, deadline, created_by, 
                  client_name, client_phone, client_organization, client_address, priority='medium'):
    """Создать новую заявку"""
    try:
        with db_connection() as db:
            cursor = db.execute(
                '''INSERT INTO requests 
                (title, description, request_type, assigned_to, deadline, created_by, 
                 client_name, client_phone, client_organization, client_address, priority) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (title, description, request_type, assigned_to, deadline, created_by,
                 client_name, client_phone, client_organization, client_address, priority)
            )
            return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error creating request: {e}")
        return None

def get_all_requests():
    """Получить все заявки"""
    try:
        with db_connection() as db:
            requests = db.execute('''
                SELECT r.*, 
                       u1.username as assigned_username,
                       u1.role as assigned_role,
                       u2.username as created_by_username
                FROM requests r
                LEFT JOIN users u1 ON r.assigned_to = u1.id
                LEFT JOIN users u2 ON r.created_by = u2.id
                ORDER BY 
                    CASE WHEN r.deadline IS NULL OR r.deadline = '' THEN 1 ELSE 0 END,
                    r.deadline ASC
            ''').fetchall()
            return [dict(req) for req in requests]
    except Exception as e:
        logger.error(f"Error getting all requests: {e}")
        return []

def get_requests_by_type(request_type):
    """Получить заявки по типу"""
    try:
        with db_connection() as db:
            requests = db.execute('''
                SELECT r.*, 
                       u1.username as assigned_username,
                       u1.role as assigned_role,
                       u2.username as created_by_username
                FROM requests r
                LEFT JOIN users u1 ON r.assigned_to = u1.id
                LEFT JOIN users u2 ON r.created_by = u2.id
                WHERE r.request_type = ?
                ORDER BY 
                    CASE WHEN r.deadline IS NULL OR r.deadline = '' THEN 1 ELSE 0 END,
                    r.deadline ASC
            ''', (request_type,)).fetchall()
            return [dict(req) for req in requests]
    except Exception as e:
        logger.error(f"Error getting requests by type: {e}")
        return []

def get_user_requests(user_id):
    """Получить заявки пользователя"""
    try:
        with db_connection() as db:
            requests = db.execute('''
                SELECT r.*, 
                       u1.username as assigned_username,
                       u1.role as assigned_role,
                       u2.username as created_by_username
                FROM requests r
                LEFT JOIN users u1 ON r.assigned_to = u1.id
                LEFT JOIN users u2 ON r.created_by = u2.id
                WHERE r.assigned_to = ? OR r.created_by = ?
                ORDER BY 
                    CASE WHEN r.deadline IS NULL OR r.deadline = '' THEN 1 ELSE 0 END,
                    r.deadline ASC
            ''', (user_id, user_id)).fetchall()
            return [dict(req) for req in requests]
    except Exception as e:
        logger.error(f"Error getting user requests: {e}")
        return []

def update_request_status(request_id, status):
    """Обновить статус заявки"""
    try:
        with db_connection() as db:
            db.execute(
                'UPDATE requests SET status = ? WHERE id = ?',
                (status, request_id)
            )
            return True
    except Exception as e:
        logger.error(f"Error updating request status: {e}")
        return False

def assign_request_to_user(request_id, user_id):
    """Назначить заявку пользователю"""
    try:
        with db_connection() as db:
            db.execute(
                'UPDATE requests SET assigned_to = ? WHERE id = ?',
                (user_id, request_id)
            )
            return True
    except Exception as e:
        logger.error(f"Error assigning request: {e}")
        return False

def update_request(request_id, update_data):
    """Обновить данные заявки"""
    try:
        with db_connection() as db:
            set_clause = ', '.join([f"{key} = ?" for key in update_data.keys()])
            values = list(update_data.values())
            values.append(request_id)
            
            query = f'UPDATE requests SET {set_clause} WHERE id = ?'
            db.execute(query, values)
            return True
    except Exception as e:
        logger.error(f"Error updating request: {e}")
        return False

def get_organizations():
    """Получить список всех организаций из заявок"""
    try:
        with db_connection() as db:
            organizations = db.execute(
                'SELECT DISTINCT client_organization FROM requests WHERE client_organization IS NOT NULL AND client_organization != "" ORDER BY client_organization'
            ).fetchall()
            return [org['client_organization'] for org in organizations]
    except Exception as e:
        logger.error(f"Error getting organizations: {e}")
        return []

# Функции для работы с документами
def create_document(document_type, document_number, request_id, client_name, client_organization, client_phone, 
                   client_email, client_address, amount, created_by, document_date, description=''):
    """Создать новый документ"""
    try:
        with db_connection() as db:
            cursor = db.execute(
                '''INSERT INTO documents 
                (document_type, document_number, request_id, client_name, client_organization, client_phone,
                 client_email, client_address, amount, created_by, document_date, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (document_type, document_number, request_id, client_name, client_organization, client_phone,
                 client_email, client_address, amount, created_by, document_date, description)
            )
            return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error creating document: {e}")
        return None

def get_documents_by_user(user_id, document_type=None):
    """Получить документы пользователя"""
    try:
        with db_connection() as db:
            if document_type:
                documents = db.execute('''
                    SELECT d.*, u.username as created_by_username
                    FROM documents d
                    LEFT JOIN users u ON d.created_by = u.id
                    WHERE d.created_by = ? AND d.document_type = ?
                    ORDER BY d.created_at DESC
                ''', (user_id, document_type)).fetchall()
            else:
                documents = db.execute('''
                    SELECT d.*, u.username as created_by_username
                    FROM documents d
                    LEFT JOIN users u ON d.created_by = u.id
                    WHERE d.created_by = ?
                    ORDER BY d.created_at DESC
                ''', (user_id,)).fetchall()
            
            return [dict(doc) for doc in documents]
    except Exception as e:
        logger.error(f"Error getting user documents: {e}")
        return []

def get_all_documents():
    """Получить все документы"""
    try:
        with db_connection() as db:
            documents = db.execute('''
                SELECT d.*, u.username as created_by_username
                FROM documents d
                LEFT JOIN users u ON d.created_by = u.id
                ORDER BY d.created_at DESC
            ''').fetchall()
            return [dict(doc) for doc in documents]
    except Exception as e:
        logger.error(f"Error getting all documents: {e}")
        return []

def update_document_status(document_id, status):
    """Обновить статус документа"""
    try:
        with db_connection() as db:
            db.execute(
                'UPDATE documents SET status = ? WHERE id = ?',
                (status, document_id)
            )
            return True
    except Exception as e:
        logger.error(f"Error updating document status: {e}")
        return False

# Функции для работы с оборудованием
def create_equipment(request_id, equipment_name, serial_number, installation_date,
                    installed_by, client_name, client_address, status, warranty_until, specifications, notes):
    """Добавить новое оборудование"""
    try:
        with db_connection() as db:
            cursor = db.execute(
                '''INSERT INTO equipment 
                (request_id, equipment_name, serial_number, installation_date,
                 installed_by, client_name, client_address, status, warranty_until, specifications, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (request_id, equipment_name, serial_number, installation_date,
                 installed_by, client_name, client_address, status, warranty_until, specifications, notes)
            )
            return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error creating equipment: {e}")
        return None

def get_equipment_by_user(user_id):
    """Получить оборудование, установленное пользователем"""
    try:
        with db_connection() as db:
            equipment = db.execute('''
                SELECT e.*, 
                       u.username as installed_by_username,
                       r.title as request_title
                FROM equipment e
                LEFT JOIN users u ON e.installed_by = u.id
                LEFT JOIN requests r ON e.request_id = r.id
                WHERE e.installed_by = ?
                ORDER BY e.installation_date DESC
            ''', (user_id,)).fetchall()
            return [dict(eq) for eq in equipment]
    except Exception as e:
        logger.error(f"Error getting user equipment: {e}")
        return []

def get_all_equipment():
    """Получить все оборудование"""
    try:
        with db_connection() as db:
            equipment = db.execute('''
                SELECT e.*, 
                       u.username as installed_by_username,
                       r.title as request_title
                FROM equipment e
                LEFT JOIN users u ON e.installed_by = u.id
                LEFT JOIN requests r ON e.request_id = r.id
                ORDER BY e.installation_date DESC
            ''').fetchall()
            return [dict(eq) for eq in equipment]
    except Exception as e:
        logger.error(f"Error getting all equipment: {e}")
        return []

def get_requests_for_equipment():
    """Получить список заявок для выбора при создании оборудования"""
    try:
        with db_connection() as db:
            requests = db.execute('''
                SELECT id, title, client_name 
                FROM requests 
                WHERE status = 'completed'
                ORDER BY created_at DESC
            ''').fetchall()
            return [dict(req) for req in requests]
    except Exception as e:
        logger.error(f"Error getting requests for equipment: {e}")
        return []

def update_equipment(equipment_id, update_data):
    """Обновить данные оборудования"""
    try:
        with db_connection() as db:
            set_clause = ', '.join([f"{key} = ?" for key in update_data.keys()])
            values = list(update_data.values())
            values.append(equipment_id)
            
            query = f'UPDATE equipment SET {set_clause} WHERE id = ?'
            db.execute(query, values)
            return True
    except Exception as e:
        logger.error(f"Error updating equipment: {e}")
        return False

def delete_equipment(equipment_id):
    """Удалить оборудование"""
    try:
        with db_connection() as db:
            db.execute('DELETE FROM equipment WHERE id = ?', (equipment_id,))
            return True
    except Exception as e:
        logger.error(f"Error deleting equipment: {e}")
        return False

# Функции для управления пользователями
def get_all_users():
    """Получить всех пользователей"""
    try:
        with db_connection() as db:
            users = db.execute(
                'SELECT id, username, role, created_at, is_active FROM users ORDER BY username'
            ).fetchall()
            return [dict(user) for user in users]
    except Exception as e:
        logger.error(f"Error getting all users: {e}")
        return []

def get_active_users():
    """Получить только активных пользователей"""
    try:
        with db_connection() as db:
            users = db.execute(
                'SELECT id, username, role, created_at, is_active FROM users WHERE is_active = 1 ORDER BY username'
            ).fetchall()
            return [dict(user) for user in users]
    except Exception as e:
        logger.error(f"Error getting active users: {e}")
        return []

def get_all_users_with_status():
    """Получить всех пользователей включая статус активности"""
    try:
        with db_connection() as db:
            users = db.execute(
                'SELECT id, username, role, created_at, is_active FROM users ORDER BY is_active DESC, username'
            ).fetchall()
            return [dict(user) for user in users]
    except Exception as e:
        logger.error(f"Error getting all users with status: {e}")
        return []

def update_user_role(user_id, new_role):
    """Обновить роль пользователя"""
    try:
        with db_connection() as db:
            db.execute(
                'UPDATE users SET role = ? WHERE id = ?',
                (new_role, user_id)
            )
            return True
    except Exception as e:
        logger.error(f"Error updating user role: {e}")
        return False

def update_user_status(user_id, is_active):
    """Обновить статус активности пользователя"""
    try:
        with db_connection() as db:
            db.execute(
                'UPDATE users SET is_active = ? WHERE id = ?',
                (is_active, user_id)
            )
            return True
    except Exception as e:
        logger.error(f"Error updating user status: {e}")
        return False

def delete_user(user_id):
    """Удалить пользователя"""
    try:
        with db_connection() as db:
            # Проверяем, есть ли у пользователя связанные данные
            user_requests = db.execute(
                'SELECT COUNT(*) as count FROM requests WHERE created_by = ? OR assigned_to = ?',
                (user_id, user_id)
            ).fetchone()
            
            user_documents = db.execute(
                'SELECT COUNT(*) as count FROM documents WHERE created_by = ?',
                (user_id,)
            ).fetchone()
            
            user_equipment = db.execute(
                'SELECT COUNT(*) as count FROM equipment WHERE installed_by = ?',
                (user_id,)
            ).fetchone()
            
            # Если есть связанные данные, не удаляем
            if (user_requests['count'] > 0 or user_documents['count'] > 0 or 
                user_equipment['count'] > 0):
                return False, 'Невозможно удалить пользователя с связанными данными'
            
            db.execute('DELETE FROM users WHERE id = ?', (user_id,))
            return True, 'Пользователь успешно удален'
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return False, str(e)

def get_user_stats(user_id):
    """Получить статистику пользователя"""
    try:
        with db_connection() as db:
            stats = db.execute('''
                SELECT 
                    (SELECT COUNT(*) FROM requests WHERE assigned_to = ?) as assigned_requests,
                    (SELECT COUNT(*) FROM requests WHERE created_by = ?) as created_requests,
                    (SELECT COUNT(*) FROM documents WHERE created_by = ?) as created_documents,
                    (SELECT COUNT(*) FROM equipment WHERE installed_by = ?) as installed_equipment
            ''', (user_id, user_id, user_id, user_id)).fetchone()
            
            return dict(stats) if stats else None
    except Exception as e:
        logger.error(f"Error getting user stats: {e}")
        return None

# Функции для поиска
def search_requests(query):
    """Поиск заявок по ключевым словам"""
    try:
        with db_connection() as db:
            search_pattern = f'%{query}%'
            requests = db.execute('''
                SELECT r.*, 
                       u1.username as assigned_username,
                       u1.role as assigned_role,
                       u2.username as created_by_username
                FROM requests r
                LEFT JOIN users u1 ON r.assigned_to = u1.id
                LEFT JOIN users u2 ON r.created_by = u2.id
                WHERE r.title LIKE ? OR r.description LIKE ? OR r.client_name LIKE ? OR r.client_organization LIKE ?
                ORDER BY 
                    CASE WHEN r.deadline IS NULL OR r.deadline = '' THEN 1 ELSE 0 END,
                    r.deadline ASC
            ''', (search_pattern, search_pattern, search_pattern, search_pattern)).fetchall()
            return [dict(req) for req in requests]
    except Exception as e:
        logger.error(f"Error searching requests: {e}")
        return []

def get_recent_requests(limit=10):
    """Получить последние заявки"""
    try:
        with db_connection() as db:
            requests = db.execute('''
                SELECT r.*, 
                       u1.username as assigned_username,
                       u1.role as assigned_role,
                       u2.username as created_by_username
                FROM requests r
                LEFT JOIN users u1 ON r.assigned_to = u1.id
                LEFT JOIN users u2 ON r.created_by = u2.id
                ORDER BY 
                    CASE WHEN r.deadline IS NULL OR r.deadline = '' THEN 1 ELSE 0 END,
                    r.deadline ASC
                LIMIT ?
            ''', (limit,)).fetchall()
            return [dict(req) for req in requests]
    except Exception as e:
        logger.error(f"Error getting recent requests: {e}")
        return []

def get_organizations_from_documents(user_id):
    """Получить список организаций из документов пользователя"""
    try:
        with db_connection() as db:
            organizations = db.execute(
                'SELECT DISTINCT client_organization FROM documents WHERE created_by = ? AND client_organization IS NOT NULL AND client_organization != "" ORDER BY client_organization',
                (user_id,)
            ).fetchall()
            return [org['client_organization'] for org in organizations]
    except Exception as e:
        logger.error(f"Error getting organizations from documents: {e}")
        return []

def get_organizations_from_equipment(user_id):
    """Получить список организаций из оборудования пользователя"""
    try:
        with db_connection() as db:
            organizations = db.execute(
                'SELECT DISTINCT client_name FROM equipment WHERE installed_by = ? AND client_name IS NOT NULL AND client_name != "" ORDER BY client_name',
                (user_id,)
            ).fetchall()
            return [org['client_name'] for org in organizations]
    except Exception as e:
        logger.error(f"Error getting organizations from equipment: {e}")
        return []

# Функции для очистки данных (для тестирования)
def clear_test_data():
    """Очистить тестовые данные (использовать с осторожностью!)"""
    try:
        with db_connection() as db:
            db.execute('DELETE FROM requests')
            db.execute('DELETE FROM documents')
            db.execute('DELETE FROM equipment')
            db.execute('DELETE FROM organizations')
            db.execute('DELETE FROM users WHERE username != "admin"')
            logger.info("Test data cleared successfully")
            return True
    except Exception as e:
        logger.error(f"Error clearing test data: {e}")
        return False

# Инициализация базы данных при импорте модуля
if not os.path.exists(DATABASE):
    logger.info(f"Database {DATABASE} not found. Initializing new database...")
    init_db()