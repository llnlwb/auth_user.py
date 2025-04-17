import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, 
                             QPushButton, QVBoxLayout, QMessageBox, QDialog)
from PyQt5.QtCore import Qt
import sqlite3
import hashlib
from datetime import datetime, timedelta

class UserAuth:
    def __init__(self, db_path='users.db'):
        self.conn = sqlite3.connect(db_path)
        self.create_table()
        
    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'user',
                        locked INTEGER DEFAULT 0,
                        failed_attempts INTEGER DEFAULT 0,
                        last_failed_attempt TEXT,
                        lock_expiry TEXT,
                        created_at TEXT NOT NULL,
                        password_reset_token TEXT,
                        reset_token_expiry TEXT)''')
        self.conn.commit()

    def authenticate(self, username, password):
        cursor = self.conn.cursor()
        try:
            cursor.execute('''SELECT password_hash, locked, lock_expiry, failed_attempts 
                           FROM users 
                           WHERE username=?''', (username,))
            result = cursor.fetchone()
            
            if not result:
                return False, "用户不存在"
                
            stored_hash, locked, lock_expiry, attempts = result
            
            if locked and datetime.now() < datetime.fromisoformat(lock_expiry):
                remaining = (datetime.fromisoformat(lock_expiry) - datetime.now()).seconds // 60
                return False, f"账户已锁定，剩余时间：{remaining}分钟"
                
            input_hash = hashlib.sha256(password.encode()).hexdigest()
            
            if input_hash != stored_hash:
                # 更新失败尝试次数
                new_attempts = attempts + 1
                lock_time = datetime.now().isoformat() if new_attempts >= 3 else None
                lock_exp = (datetime.now() + timedelta(minutes=5)).isoformat() if new_attempts >=3 else None
                
                cursor.execute('''UPDATE users SET 
                                failed_attempts=?, 
                                last_failed_attempt=?, 
                                locked=?, 
                                lock_expiry=?
                                WHERE username=?''',
                             (new_attempts, lock_time, new_attempts>=3, lock_exp, username))
                self.conn.commit()
                
                if new_attempts >= 3:
                    return False, "密码错误次数过多，账户已锁定5分钟"
                return False, f"密码错误，剩余尝试次数：{3 - new_attempts}"
                
            # 重置失败计数器
            cursor.execute('''UPDATE users SET 
                            failed_attempts=0, 
                            locked=0, 
                            lock_expiry=NULL
                            WHERE username=?''', (username,))
            self.conn.commit()
            return True, "认证成功"
            
        except Exception as e:
            return False, f"登录失败：{str(e)}"

    def create_user(self, username, password, role='user'):
        if not self.validate_password_complexity(password):
            return False, "密码必须包含大小写字母、数字和特殊字符，且长度至少8位"
            
        cursor = self.conn.cursor()
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            created_at = datetime.now().isoformat()
            cursor.execute('''INSERT INTO users 
                            (username, password_hash, role, created_at)
                            VALUES (?, ?, ?, ?)''',
                         (username, password_hash, role, created_at))
            self.conn.commit()
            return True, "用户注册成功"
        except sqlite3.IntegrityError:
            return False, "用户名已存在"
        except Exception as e:
            return False, f"数据库错误: {str(e)}"

    def validate_password_complexity(self, password):
        if len(password) < 8:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?~' for c in password):
            return False
        return True

class MainDialog(QDialog):
    def __init__(self, auth_system):
        super().__init__()
        self.auth_system = auth_system
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('用户认证')
        self.setFixedSize(300, 150)
        
        layout = QVBoxLayout()
        
        self.btn_login = QPushButton('登录')
        self.btn_login.clicked.connect(self.open_login)
        
        self.btn_register = QPushButton('注册')
        self.btn_register.clicked.connect(self.open_register)
        
        layout.addWidget(self.btn_login)
        layout.addWidget(self.btn_register)
        self.setLayout(layout)
    
    def open_login(self):
        self.hide()
        login_dialog = LoginDialog(self.auth_system)
        if login_dialog.exec_() == QDialog.Accepted:
            self.accept()
        else:
            self.show()
    
    def open_register(self):
        self.hide()
        register_dialog = RegisterDialog(self.auth_system)
        if register_dialog.exec_() == QDialog.Accepted:
            self.show()
            
class LoginDialog(QDialog):
    def __init__(self, auth_system):
        super().__init__()
        self.auth_system = auth_system
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('用户登录')
        self.setFixedSize(300, 200)
        
        layout = QVBoxLayout()
        
        self.lbl_username = QLabel('用户名:')
        self.txt_username = QLineEdit()
        
        self.lbl_password = QLabel('密码:')
        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.Password)
        
        self.btn_login = QPushButton('登录')
        self.btn_login.clicked.connect(self.authenticate_user)
        
        layout.addWidget(self.lbl_username)
        layout.addWidget(self.txt_username)
        layout.addWidget(self.lbl_password)
        layout.addWidget(self.txt_password)
        layout.addWidget(self.btn_login)
        
        self.setLayout(layout)
    
    def authenticate_user(self):
        username = self.txt_username.text().strip()
        password = self.txt_password.text().strip()
        
        if not username or not password:
            QMessageBox.warning(self, '输入错误', '用户名和密码不能为空')
            return
            
        success, message = self.auth_system.authenticate(username, password)
        if success:
            QMessageBox.information(self, '登录成功', '认证成功，正在跳转主界面...')
            self.accept()
        else:
            QMessageBox.critical(self, '登录失败', message)

class RegisterDialog(QDialog):
    def __init__(self, auth_system):
        super().__init__()
        self.auth_system = auth_system
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('用户注册')
        self.setFixedSize(300, 250)
        
        layout = QVBoxLayout()
        
        self.lbl_username = QLabel('用户名:')
        self.txt_username = QLineEdit()
        
        self.lbl_password = QLabel('密码:')
        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.Password)
        
        self.lbl_confirm = QLabel('确认密码:')
        self.txt_confirm = QLineEdit()
        self.txt_confirm.setEchoMode(QLineEdit.Password)
        
        self.btn_register = QPushButton('注册')
        self.btn_register.clicked.connect(self.register_user)
        
        layout.addWidget(self.lbl_username)
        layout.addWidget(self.txt_username)
        layout.addWidget(self.lbl_password)
        layout.addWidget(self.txt_password)
        layout.addWidget(self.lbl_confirm)
        layout.addWidget(self.txt_confirm)
        layout.addWidget(self.btn_register)
        
        self.setLayout(layout)
    
    def register_user(self):
        username = self.txt_username.text().strip()
        password = self.txt_password.text().strip()
        confirm = self.txt_confirm.text().strip()
        
        if not username or not password:
            QMessageBox.warning(self, '输入错误', '用户名和密码不能为空')
            return
            
        if password != confirm:
            QMessageBox.warning(self, '输入错误', '两次输入的密码不一致')
            return
            
        success, message = self.auth_system.create_user(username, password)
        if success:
            QMessageBox.information(self, '注册成功', message)
            self.accept()
        else:
            QMessageBox.critical(self, '注册失败', message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    auth_system = UserAuth()
    main_dialog = MainDialog(auth_system)
    main_dialog.exec_()
    sys.exit(app.exec_())
