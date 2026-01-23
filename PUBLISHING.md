# Publishing HYDRA7 to PyPI

This guide explains how to publish the HYDRA7 package to PyPI (Python Package Index).

## Prerequisites

1. **PyPI Account**: Create accounts at:
   - Production: https://pypi.org/account/register/
   - Test: https://test.pypi.org/account/register/

2. **Install build tools**:
   ```bash
   pip install --upgrade build twine
   ```

3. **API Token**: Generate an API token at:
   - Production: https://pypi.org/manage/account/token/
   - Test: https://test.pypi.org/manage/account/token/

## Step-by-Step Publishing

### 1. Prepare the Package

Ensure all files are committed and the version number is correct:

```bash
# Check version in pyproject.toml and hydra7/__init__.py
grep "version" pyproject.toml
grep "__version__" hydra7/__init__.py
```

### 2. Clean Previous Builds

```bash
# Remove old build artifacts
rm -rf build/ dist/ *.egg-info hydra7.egg-info
```

### 3. Build Distribution Packages

```bash
# Build both wheel and source distribution
python3 -m build
```

This creates:
- `dist/hydra7-X.Y.Z-py3-none-any.whl` (wheel package)
- `dist/hydra7-X.Y.Z.tar.gz` (source distribution)

### 4. Test the Distribution

Verify the package is valid:

```bash
# Check package with twine
python3 -m twine check dist/*
```

Test installation in a virtual environment:

```bash
# Create test environment
python3 -m venv test_venv
source test_venv/bin/activate  # On Windows: test_venv\Scripts\activate

# Install from the built wheel
pip install dist/hydra7-*.whl

# Test the installation
hydra7 --version
python -m hydra7.cli --version
python -c "import hydra7; print(hydra7.__version__)"

# Cleanup
deactivate
rm -rf test_venv
```

### 5. Upload to Test PyPI (Optional but Recommended)

Test the upload process first:

```bash
# Upload to Test PyPI
python3 -m twine upload --repository testpypi dist/*
```

When prompted, use:
- Username: `__token__`
- Password: Your Test PyPI API token (starts with `pypi-`)

Test installation from Test PyPI:

```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ hydra7
```

Note: `--extra-index-url` is needed because dependencies (like `cryptography`) are on production PyPI.

### 6. Upload to Production PyPI

Once everything is tested:

```bash
# Upload to production PyPI
python3 -m twine upload dist/*
```

When prompted, use:
- Username: `__token__`
- Password: Your PyPI API token (starts with `pypi-`)

### 7. Verify Installation

After uploading, verify anyone can install:

```bash
# Wait a minute for PyPI to index the package
pip install hydra7

# Test it works
hydra7 --version
```

## Automated Publishing with GitHub Actions (Optional)

Create `.github/workflows/publish.yml`:

```yaml
name: Publish to PyPI

on:
  release:
    types: [published]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.x'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install build twine
    - name: Build package
      run: python -m build
    - name: Publish to PyPI
      env:
        TWINE_USERNAME: __token__
        TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
      run: twine upload dist/*
```

Add your PyPI API token as a secret named `PYPI_API_TOKEN` in your GitHub repository settings.

## Version Management

When releasing a new version:

1. Update version in both:
   - `pyproject.toml`
   - `hydra7/__init__.py`

2. Commit the version bump:
   ```bash
   git add pyproject.toml hydra7/__init__.py
   git commit -m "Bump version to X.Y.Z"
   git tag -a vX.Y.Z -m "Release version X.Y.Z"
   git push && git push --tags
   ```

3. Follow the publishing steps above

## Troubleshooting

### Common Issues

1. **"File already exists" error**:
   - You cannot re-upload the same version
   - Bump the version number and rebuild

2. **"Invalid distribution" error**:
   - Run `twine check dist/*` to identify issues
   - Ensure README.md is properly formatted

3. **Import errors after installation**:
   - Check that all required files are in MANIFEST.in
   - Verify package structure with `tar -tzf dist/*.tar.gz`

## Security Best Practices

1. **Never commit API tokens** to version control
2. Use **API tokens** instead of passwords
3. Create **project-scoped tokens** when possible
4. Store tokens in:
   - Environment variables
   - GitHub Secrets (for CI/CD)
   - Secure password manager

## Resources

- PyPI: https://pypi.org/
- Test PyPI: https://test.pypi.org/
- Packaging Guide: https://packaging.python.org/
- Twine: https://twine.readthedocs.io/
