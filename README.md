# UserManagementAPI_DEV

```bash
pip install -r app/requirements.txt
pip install -r app/test/requirements-dev.txt

fastapi dev app/main.py
fastapi dev app/main.py --host 0.0.0.0

pylint app/ 
pylint app/ --fail-under=8 --output-format=parseable | tee reports/pylint-report.txt

pytest --tb=no --md-report --md-report-verbose=1
pytest --tb=no --md-report --md-report-output=reports/pytest.md

coverage run -m pytest --tb=no --md-report
coverage run -m pytest --tb=no --md-report --md-report-output=reports/pytest.md 
coverage report | tee reports/coverage.txt
coverage run -m pytest --tb=no --md-report --md-report-verbose=1 | coverage html

cd app
alembic revision --autogenerate -m "describe your changes"
```