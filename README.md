# Mobile POS App

A REST API for mobile point-of-sale systems built with Django and Django REST Framework. Enables secure payment processing with SMS verification and comprehensive vehicle management features.

## ✨ Features

- JWT Authentication
- OTP verification via SMS
- User management (register, login, profile update)
- Vehicle plate management
- Payment processing and history
- IYS (Communication Management System) integration
- AWS S3 integration
- Webhook support
- Automated tasks with Celery & Redis

## 🛠 Tech Stack

- Python 3.9
- Django 4.0.7
- Django REST Framework
- PostgreSQL
- Celery & Redis
- AWS S3

## 🚀 Quick Start

1. Clone and install requirements:
```bash
git clone https://github.com/yourusername/mobile-pos-app.git
cd mobile-pos-app
pip install -r requirements.txt
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env file with your settings
```

3. Run migrations:
```bash
python manage.py migrate
```

4. Start the server:
```bash
python manage.py runserver
```

## 🧪 Testing

```bash
python manage.py test api.tests
```
