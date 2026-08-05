# Contributing

Thanks for your interest in improving FreeShare! It's a small project, so the
process is light.

## Getting set up

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

Run the app locally:

```bash
export ADMIN_PASSWORD='test'
python3 app.py        # http://localhost:8000
```

Run the tests:

```bash
python -m pytest
```

## Guidelines

- Keep it simple. FreeShare is meant to be a small, readable, single-file app
  that anyone can host. New features should earn their complexity.
- Add or update a test in `tests/test_app.py` for any behaviour change.
- Please make sure `python -m pytest` passes before opening a pull request (CI
  runs it on Python 3.9, 3.11, and 3.12).
- For anything larger than a small fix, opening an issue first to discuss is
  appreciated.

## Reporting bugs

Open an issue with what you expected, what happened, and the steps to reproduce.
Screenshots help for anything visual.
