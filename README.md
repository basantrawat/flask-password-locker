# 🔐 Password Locker

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)  [![Made with Python](https://img.shields.io/badge/Made%20with-Python-blue.svg)](https://www.python.org/)  [![Flask](https://img.shields.io/badge/Framework-Flask-orange.svg)](https://flask.palletsprojects.com/)

## Overview

Password Locker is a Flask-based web application designed to keep your account details safe, secure, and easily accessible. It helps you manage your passwords efficiently while ensuring top-level protection.

---

## Features

- Secure storage of account credentials
- User-friendly interface built with Flask, HTML, CSS, and JavaScript
- Easy account addition, update, and deletion
- Password encryption and security best practices (if applicable)
- Responsive design for desktop and mobile

---

## Screenshots

**Login Page**
<img src="bin/screenshots/login_page.jpg" alt="Login Page" width="50%" />
*Login page for secure access*

**Dashboard**
<img src="bin/screenshots/dashboard.jpg" alt="Dashboard" width="50%" />
*Dashboard to view and manage passwords*

**Add New Details**
<img src="bin/screenshots/add_details.jpg" alt="Add New Details" width="50%" />
*Form to add new account details*

**Profile Settings**
<img src="bin/screenshots/profile-settings.jpg" alt="Profile Settings" width="50%" />
*User profile settings page*

**Password Audit**
<img src="bin/screenshots/password-audit.jpg" alt="Password Audit" width="50%" />
*Password audit and analysis dashboard*

---

## Installation

Follow these steps to set up and run Password Locker locally:

1. **Clone the repository**  
   ```
   git clone https://github.com/basantrawat/Password-Locker.git
   cd Password-Locker
   ```

2. **Create and activate a virtual environment**  
   ```
   python3 -m venv venv
   source venv/bin/activate   # On Windows use: venv\Scripts\activate
   ```

3. **Install dependencies**  
   ```
   pip install -r requirements.txt
   ```

4. **Create the database**  
   The database file is not included, so create your own database named `pass_locker` following the necessary schema.

5. **Run the app**  
   ```
   flask run
   ```
   Open your browser and navigate to `http://127.0.0.1:5000`

---

## Usage

- Register or login with your credentials.
- Add new account details securely.
- Update or delete existing accounts.
- Explore and manage your stored credentials easily.

---

## Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Database:** MySQL

---


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---


*Thank you for using Password Locker! Stay safe and secure.*  
