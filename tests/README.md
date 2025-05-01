# 🧪 Tests

This folder contains unit tests for the **pyproxy** project. The tests cover different modules and utilities to ensure the proxy server works correctly and efficiently.

## 🏃‍♂️ Running All Tests

To run all tests in the `tests/` folder, simply use the following command:

```bash
python3 -m unittest discover -s tests
```

This will discover and run all test files in the `tests/` folder.

## 🧩 Running Tests for a Specific Module

If you want to run tests for a specific module, such as the `utils` module, you can specify the module like this:

```bash
python3 -m unittest discover -s tests/utils
```

This will only run tests in the `tests/utils` folder.

## 📄 Running Tests for a Specific File

To run tests from a specific test file, for example `test_crypto.py` in the `utils` folder, use the following command:

```bash
python3 -m unittest tests/utils/test_crypto.py
```

This will run only the tests in the `test_crypto.py` file.

## 🔍 Running a Specific Test

If you need to run a specific test case, such as the `test_generate_certificate` from `test_crypto.py`, you can specify the exact test method like this:

```bash
python3 -m unittest tests.utils.test_crypto.TestCrypto.test_generate_certificate
```

This will run just the `test_generate_certificate` method from the `TestCrypto` class.

---