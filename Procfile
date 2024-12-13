web: gunicorn pos_project.wsgi --log-file -
main_worker: celery -A pos_project worker -B -l INFO --without-gossip --without-mingle --without-heartbeat
release: python manage.py migrate