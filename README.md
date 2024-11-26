# UserManagementAPI_DEV

```bash
pip install -r app/requirements.txt
pip install -r app/test/requirements.txt

# DEV (.root)
fastapi dev app/main.py --host=localhost --port=80
pylint app/ --rcfile=app/.pylintrc
pytest app/ --tb=no --md-report --md-report-verbose=1
coverage run -m pytest app/ --tb=no --md-report --md-report-verbose=1
coverage run -m pytest app/ | coverage html

# DEV (.root/app)
fastapi dev main.py --host=localhost --port=80
pylint .
pytest --tb=no --md-report --md-report-verbose=1
coverage run -m pytest --tb=no --md-report --md-report-verbose=1
coverage run -m pytest | coverage html

# DEV
alembic revision --autogenerate -m "<describe your changes>"

# PROD
fastapi run app/main.py --host=localhost --port=80
pylint app/ --fail-under=8 --output-format=parseable | tee app/reports/pylint-report.txt
pytest app/ --tb=no --md-report --md-report-output=app/reports/pytest.md
coverage run -m pytest app/ | coverage report
coverage report | tee reports/coverage.txt
```
