import sys
import sqlite3
import re
import hashlib
import os
import datetime
from PyQt5.QtWidgets import QTextEdit, QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QFormLayout, QLineEdit, QPushButton, QMessageBox, QCheckBox, QComboBox, QLabel
from PyQt5.QtCore import QTimer


# Налаштування
discipline = "TBD"
surname = "Levchuk"
database_directory = f"{discipline}_{surname}"
database_file = f"{database_directory}/users.db"

# Створення директорії, якщо вона не існує
if not os.path.exists(database_directory):
    os.makedirs(database_directory)

# Підключення до бази даних
db = sqlite3.connect(database_file)
cursor = db.cursor()
# Створення таблиць
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, 
        username TEXT UNIQUE, 
        password TEXT
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS password_history (
        user_id INTEGER,
        password TEXT,
        change_date TIMESTAMP,
        expiration_date TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY, 
        name TEXT UNIQUE
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS permissions (
        id INTEGER PRIMARY KEY, 
        name TEXT UNIQUE
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_roles (
        user_id INTEGER,
        role_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(role_id) REFERENCES roles(id)
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS role_permissions (
        role_id INTEGER,
        permission_id INTEGER,
        FOREIGN KEY(role_id) REFERENCES roles(id),
        FOREIGN KEY(permission_id) REFERENCES permissions(id)
    )
''')

# Додавання початкових ролей і прав доступу
cursor.execute("INSERT INTO roles (name) VALUES ('Адміністратор'), ('Користувач')")
cursor.execute("INSERT INTO permissions (name) VALUES ('Читання'), ('Редагування'), ('Збереження')")

# Зберігання змін
db.commit()

# Функції для обробки паролів
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def is_complex_password(password):
    if len(password) < 8:
        return False
    char_sets = [r'[a-z]', r'[A-Z]', r'[0-9]', r'[^a-zA-Z0-9]']
    return sum(bool(re.search(char_set, password)) for char_set in char_sets) >= 3

def save_old_password(user_id, old_password, expiration_days=30):
    change_date = datetime.datetime.now()
    expiration_date = change_date + datetime.timedelta(days=expiration_days)
    cursor.execute("INSERT INTO password_history (user_id, password, change_date, expiration_date) VALUES (?, ?, ?, ?)",
                   (user_id, old_password, change_date, expiration_date))
    db.commit()

def is_old_password(user_id, new_password_hash):
    cursor.execute("SELECT password FROM password_history WHERE user_id = ? ORDER BY change_date DESC LIMIT 3",
                   (user_id,))
    last_passwords = [row[0] for row in cursor.fetchall()]
    return new_password_hash in last_passwords

def is_password_expired(user_id):
    cursor.execute("SELECT expiration_date FROM password_history WHERE user_id = ? ORDER BY change_date DESC LIMIT 1",
                   (user_id,))
    last_expiration = cursor.fetchone()
    if last_expiration:
        last_expiration_date = datetime.datetime.strptime(last_expiration[0], "%Y-%m-%d %H:%M:%S.%f")
        return datetime.datetime.now() > last_expiration_date
    return False

# Головне вікно додатку
class MainWindow(QMainWindow):
    def __init__(self, app_title):
        super().__init__()
        self.setWindowTitle(app_title)
        self.setGeometry(100, 100, 600, 400)
        self.current_user_id = None
        self.failed_login_attempts = {}  # Словник для відстеження спроб входу
        self.locked_users = {}  # Словник для відстеження заблокованих користувачів
        self.initUI()

    def initUI(self):
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.central_widget.setLayout(self.layout)

        self.register_button = QPushButton("Зареєструвати користувача", self)
        self.register_button.clicked.connect(self.show_register_form)
        self.layout.addWidget(self.register_button)

        self.login_button = QPushButton("Увійти", self)
        self.login_button.clicked.connect(self.show_login_form)
        self.layout.addWidget(self.login_button)

        self.change_password_button = QPushButton("Змінити пароль", self)
        self.change_password_button.clicked.connect(self.show_change_password_form)
        self.change_password_button.setEnabled(False)
        self.layout.addWidget(self.change_password_button)

        self.add_user_interface()
        self.add_login_interface()
        self.add_change_password_interface()

        # Додавання кнопки для управління ролями
        self.manage_roles_button = QPushButton("Управління ролями", self)
        self.manage_roles_button.clicked.connect(self.show_manage_roles_dialog)
        self.layout.addWidget(self.manage_roles_button)

        # Додавання кнопки для управління правами доступу
        self.manage_permissions_button = QPushButton("Управління правами доступу", self)
        self.manage_permissions_button.clicked.connect(self.show_manage_permissions_dialog)
        self.layout.addWidget(self.manage_permissions_button)
        # Додавання нових кнопок
        self.open_file_button = QPushButton("Відкрити Файл", self)
        self.open_file_button.clicked.connect(self.open_file_dialog)
        self.save_button = QPushButton("Зберегти", self)
        self.edit_button = QPushButton("Редагувати", self)

        # Активація кнопки "Зберегти"
        self.save_button.setEnabled(True)
        self.save_button.clicked.connect(self.save_file)

        self.edit_button.setEnabled(True)
        self.edit_button.clicked.connect(self.edit_file)

        # Додавання кнопок до головного вікна
        self.button_layout = QHBoxLayout()
        self.button_layout.addWidget(self.open_file_button)
        self.button_layout.addWidget(self.save_button)
        self.button_layout.addWidget(self.edit_button)
        self.layout.addLayout(self.button_layout)
    def save_file(self):
        # Створення нового вікна для редагування тексту
        self.text_edit_window = QTextEdit()
        self.text_edit_window.setWindowTitle("Редагування та збереження файлу")

        # Читання файлу та відображення його вмісту для редагування
        try:
            with open("text.txt", "r") as file:
                self.text_edit_window.setText(file.read())
        except FileNotFoundError:
            self.text_edit_window.setText("Файл не знайдено.")

        # Додавання кнопки "Зберегти зміни" в вікно редагування
        self.save_changes_button = QPushButton("Зберегти зміни", self.text_edit_window)
        self.save_changes_button.clicked.connect(self.save_changes)
        self.text_edit_window.show()

    def save_changes(self):
        # Збереження змін у файлі
        text_to_save = self.text_edit_window.toPlainText()
        try:
            with open("text.txt", "w") as file:
                file.write(text_to_save)
            QMessageBox.information(self, "Успіх", "Файл успішно збережено.")
        except Exception as e:
            QMessageBox.warning(self, "Помилка", f"Помилка при збереженні файлу: {e}")

    def edit_file(self):
        # Створення нового вікна для редагування тексту
        self.text_edit_window = QTextEdit()
        self.text_edit_window.setWindowTitle("Редагування файлу")

        # Читання файлу та відображення його вмісту для редагування
        try:
            with open("text.txt", "r") as file:
                self.text_edit_window.setText(file.read())
        except FileNotFoundError:
            self.text_edit_window.setText("Файл не знайдено.")

        # Встановлення режиму редагування (за замовчуванням в QTextEdit вже включено)
        # self.text_edit_window.setReadOnly(False)  # Ця лінія не потрібна, оскільки режим редагування вже активний

        self.text_edit_window.show()
    def open_file_dialog(self):
        # Створення нового вікна для відображення тексту
        self.text_window = QTextEdit()
        self.text_window.setWindowTitle("Вміст файлу")

        # Читання файлу та відображення його вмісту
        try:
            with open("text.txt", "r") as file:
                self.text_window.setText(file.read())
        except FileNotFoundError:
            self.text_window.setText("Файл не знайдено.")

        self.text_window.setReadOnly(True)
        self.text_window.show()


    def show_manage_roles_dialog(self):
        # Створення вікна для управління ролями
        self.manage_roles_widget = QWidget()
        self.manage_roles_layout = QVBoxLayout(self.manage_roles_widget)
        
        # Додавання елементів форми
        self.role_name_input = QLineEdit()
        self.add_role_button = QPushButton("Додати роль")
        self.add_role_button.clicked.connect(self.add_role)
        self.remove_role_button = QPushButton("Видалити роль")
        self.remove_role_button.clicked.connect(self.remove_role)

        self.manage_roles_layout.addWidget(self.role_name_input)
        self.manage_roles_layout.addWidget(self.add_role_button)
        self.manage_roles_layout.addWidget(self.remove_role_button)

        self.manage_roles_widget.show()
        
    def add_role(self):
        # Отримуємо назву ролі з поля вводу
        role_name = self.role_name_input.text()
        if role_name:
            try:
                cursor.execute("INSERT INTO roles (name) VALUES (?)", (role_name,))
                db.commit()
                QMessageBox.information(self, "Успіх", f"Роль '{role_name}' успішно додано.")
            except sqlite3.IntegrityError:
                QMessageBox.warning(self, "Помилка", f"Роль з назвою '{role_name}' вже існує.")
        else:
            QMessageBox.warning(self, "Помилка", "Назва ролі не може бути порожньою.")

    def remove_role(self):
        # Отримуємо назву ролі з поля вводу
        role_name = self.role_name_input.text()
        if role_name:
            cursor.execute("DELETE FROM roles WHERE name = ?", (role_name,))
            if cursor.rowcount > 0:
                db.commit()
                QMessageBox.information(self, "Успіх", f"Роль '{role_name}' успішно видалено.")
            else:
                QMessageBox.warning(self, "Помилка", f"Роль з назвою '{role_name}' не знайдено.")
        else:
            QMessageBox.warning(self, "Помилка", "Назва ролі не може бути порожньою.")

    def show_manage_permissions_dialog(self):
        # Створення вікна для управління правами доступу
        self.manage_permissions_widget = QWidget()
        self.manage_permissions_layout = QVBoxLayout(self.manage_permissions_widget)
        
        # Вибір ролі
        self.role_selection_label = QLabel("Виберіть роль:")
        self.role_selection_combobox = QComboBox()
        self.load_roles_into_combobox()  # Завантажити доступні ролі

        # Чекбокси для доступів
        self.permissions_checkboxes = {}
        for permission in ["Читання", "Редагування", "Збереження"]:
            self.permissions_checkboxes[permission] = QCheckBox(permission)

        # Додавання елементів у макет
        self.manage_permissions_layout.addWidget(self.role_selection_label)
        self.manage_permissions_layout.addWidget(self.role_selection_combobox)
        for permission, checkbox in self.permissions_checkboxes.items():
            self.manage_permissions_layout.addWidget(checkbox)

        # Кнопки для застосування змін
        self.apply_permissions_button = QPushButton("Застосувати зміни")
        self.apply_permissions_button.clicked.connect(self.apply_permissions_changes)

        self.manage_permissions_layout.addWidget(self.apply_permissions_button)
        self.manage_permissions_widget.show()

    def load_roles_into_combobox(self):
        # Завантажити ролі з бази даних
        cursor.execute("SELECT name FROM roles")
        roles = cursor.fetchall()
        self.role_selection_combobox.clear()
        for role in roles:
            self.role_selection_combobox.addItem(role[0])

    def apply_permissions_changes(self):
        selected_role_name = self.role_selection_combobox.currentText()
        selected_permissions = [perm for perm, cb in self.permissions_checkboxes.items() if cb.isChecked()]

        # Отримати ID вибраної ролі
        cursor.execute("SELECT id FROM roles WHERE name = ?", (selected_role_name,))
        role_id = cursor.fetchone()
        if role_id is None:
            QMessageBox.warning(self, "Помилка", "Роль не знайдена.")
            return
        role_id = role_id[0]

        # Очистити існуючі права доступу для ролі
        cursor.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))

        # Додати нові права доступу
        for permission_name in selected_permissions:
            # Отримати ID права доступу
            cursor.execute("SELECT id FROM permissions WHERE name = ?", (permission_name,))
            permission_id = cursor.fetchone()
            if permission_id is None:
                continue  # Якщо право доступу не знайдено, пропустити
            permission_id = permission_id[0]

            # Створити нову прив'язку між роллю та правом доступу
            cursor.execute("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)", (role_id, permission_id))

        db.commit()
        QMessageBox.information(self, "Успіх", "Права доступу оновлено.")

    def add_user_interface(self):
        self.registration_widget = QWidget()
        self.registration_form = QFormLayout()
        self.username_reg_input = QLineEdit()
        self.password_reg_input = QLineEdit()
        self.password_reg_input.setEchoMode(QLineEdit.Password)
        self.password_expiration_input = QLineEdit()
        self.password_expiration_input.setPlaceholderText("Термін дії пароля в днях (за замовчуванням 30)")
        self.register_button = QPushButton("Зареєструвати")
        self.register_button.clicked.connect(self.register_user)
        self.registration_form.addRow("Ім'я користувача:", self.username_reg_input)
        self.registration_form.addRow("Пароль:", self.password_reg_input)
        self.registration_form.addRow("Термін дії пароля:", self.password_expiration_input)
        self.registration_form.addWidget(self.register_button)
        self.registration_widget.setLayout(self.registration_form)
        self.registration_widget.hide()
        self.layout.addWidget(self.registration_widget)
        

    def add_login_interface(self):
        self.login_widget = QWidget()
        self.login_form = QFormLayout()
        self.username_login_input = QLineEdit()
        self.password_login_input = QLineEdit()
        self.password_login_input.setEchoMode(QLineEdit.Password)
        self.login_button = QPushButton("Увійти")
        self.login_button.clicked.connect(self.login_user)
        self.login_form.addRow("Ім'я користувача:", self.username_login_input)
        self.login_form.addRow("Пароль:", self.password_login_input)
        self.login_form.addWidget(self.login_button)
        self.login_widget.setLayout(self.login_form)
        self.login_widget.hide()
        self.layout.addWidget(self.login_widget)

    def add_change_password_interface(self):
        self.change_password_widget = QWidget()
        self.change_password_form = QFormLayout()
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)
        self.change_password_button = QPushButton("Змінити пароль")
        self.change_password_button.clicked.connect(self.change_password)
        self.change_password_form.addRow("Новий пароль:", self.new_password_input)
        self.change_password_form.addWidget(self.change_password_button)
        self.change_password_widget.setLayout(self.change_password_form)
        self.change_password_widget.hide()
        self.layout.addWidget(self.change_password_widget)

    def show_register_form(self):
        self.registration_widget.setVisible(not self.registration_widget.isVisible())

    def show_login_form(self):
        self.login_widget.setVisible(not self.login_widget.isVisible())

    def show_change_password_form(self):
            self.change_password_widget.setVisible(True)  # Забезпечити, що віджет видимий

    def register_user(self):
        username = self.username_reg_input.text()
        password = self.password_reg_input.text()
        if not is_complex_password(password):
            QMessageBox.warning(self, "Помилка", "Пароль не є складним.")
            return
        hashed_password = hash_password(password)
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            user_id = cursor.lastrowid
            save_old_password(user_id, hashed_password)
            QMessageBox.information(self, "Успіх", "Користувача зареєстровано.")
            self.registration_widget.hide()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Помилка", "Такий користувач вже існує.")

    def login_user(self):
        username = self.username_login_input.text()
        username = self.username_login_input.text()
        if username not in self.failed_login_attempts:
            self.failed_login_attempts[username] = 0

        if self.failed_login_attempts[username] >= 3:
            QMessageBox.warning(self, "Блокування", "Ваш акаунт заблоковано через занадто багато спроб входу.")
            return
        if username in self.locked_users and self.locked_users[username].isActive():
            QMessageBox.warning(self, "Блокування", "Ваш акаунт тимчасово заблоковано.")
            return
        password = self.password_login_input.text()
        hashed_password = hash_password(password)
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and user[1] == hashed_password:
            self.failed_login_attempts[username] = 0  # Скидаємо лічильник спроб при успішному вході
            self.current_user_id = user[0]
            if is_password_expired(user[0]):
                QMessageBox.warning(self, "Помилка", "Термін дії пароля закінчився.")
                return

            self.current_user_id = user[0]
            self.change_password_button.setEnabled(True)
            self.show_change_password_form()  # Відразу показати форму для зміни пароля
            QMessageBox.information(self, "Успіх", "Успішний вхід.")
            self.login_widget.hide()
        else:
            self.failed_login_attempts[username] += 1
            if self.failed_login_attempts[username] >= 3:
                QMessageBox.warning(self, "Блокування", "Ваш акаунт заблоковано на 1 хвилину.")
                self.failed_login_attempts[username] = 0
                self.lock_account()
                self.locked_users[username] = QTimer()
                self.locked_users[username].singleShot(60000, self.unlock_account)  # 60000 мс = 1 хвилина
            else:
                QMessageBox.warning(self, "Помилка", "Неправильне ім'я користувача або пароль.")
                
    def lock_account(self):
        self.register_button.setEnabled(False)
        self.login_button.setEnabled(False)
        self.change_password_button.setEnabled(False)

    def unlock_account(self):
        self.register_button.setEnabled(True)
        self.login_button.setEnabled(True)



    def change_password(self):
        new_password = self.new_password_input.text()
        if not is_complex_password(new_password):
            QMessageBox.warning(self, "Помилка", "Пароль не є складним.")
            return
        new_password_hash = hash_password(new_password)
        if is_old_password(self.current_user_id, new_password_hash):
            QMessageBox.warning(self, "Помилка", "Цей пароль вже використовувався.")
            return
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password_hash, self.current_user_id))
        save_old_password(self.current_user_id, new_password_hash)
        db.commit()
        QMessageBox.information(self, "Успіх", "Пароль успішно змінено.")
        self.change_password_widget.hide()

# Запуск додатку
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app_title = f"{discipline}_{surname}"
    mainWin = MainWindow(app_title)
    mainWin.show()
    sys.exit(app.exec_())