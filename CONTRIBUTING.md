# Contributing

Thanks for your interest in contributing! 💻🐍  
Whether you're fixing bugs, writing tests, or improving documentation, all contributions are welcome.

## 🛠️ Getting Started

1. Fork this repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/project-name.git
   cd project-name
   ```
3. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## ✅ Development Guidelines

- Follow [PEP8](https://peps.python.org/pep-0008/) coding style.
- We use **pylint** to ensure code quality:
  ```bash
  pylint $(find . -name "*.py" | xargs)
  ```
- Tests are written using **unittest**. To run all tests:
  ```bash
  python3 -m unittest discover -s tests
  ```
- Add or update tests when fixing bugs or adding features.

## 📝 Commit Messages

Use clear and concise commit messages:
```bash
git commit -m "Fix: correct issue with user authentication"
```

## 🚀 Submitting a Pull Request

1. Push your changes:
   ```bash
   git push origin feature/your-feature-name
   ```
2. Open a pull request on the original repository
3. Describe your changes clearly

## 🐞 Reporting Issues

If you find bugs or have suggestions, open an issue with as much detail as possible.
