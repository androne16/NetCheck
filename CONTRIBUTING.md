# Contributing to NetCheck

Thank you for considering contributing to NetCheck!

## How to Contribute

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```powershell
   git clone https://github.com/YOUR-USERNAME/NetCheck.git
   cd NetCheck
   ```
3. **Create a feature branch**:
   ```powershell
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes** following the guidelines below
5. **Test your changes** by running the script:
   ```powershell
   .\netcheck.ps1
   ```
6. **Commit your changes**:
   ```powershell
   git add .
   git commit -m "Brief description of changes"
   ```
7. **Push to your fork**:
   ```powershell
   git push origin feature/your-feature-name
   ```
8. **Open a Pull Request** on the main repository

## Coding Guidelines

### PowerShell Style
- Use 4 spaces for indentation (not tabs)
- Use `PascalCase` for function names
- Use `$camelCase` for variable names
- Include comment-based help for new functions
- Keep lines under 120 characters when possible

### Testing
- Test scripts on Windows PowerShell 5.1 and PowerShell 7+
- Verify output files are created correctly in `C:\temp\netcheck\`
- Test both with and without Administrator privileges

### Documentation
- Update `README.md` if adding new features or switches
- Add entries to `docs/` for significant new functionality
- Include inline comments for complex logic

## Project Structure

```
NetCheck/
├── netcheck.ps1           # Main stable script
├── netcheck.jitter.ps1    # Jitter-focused test track
├── docs/                  # Documentation
├── .github/               # GitHub-specific files
└── README.md              # Project overview
```

## Reporting Issues

- Use GitHub Issues to report bugs or suggest features
- Include PowerShell version, Windows version, and error messages
- Attach relevant output files from `C:\temp\netcheck\` if applicable

## Code of Conduct

Be respectful and constructive in all interactions.

## Questions?

Open an issue or discussion on GitHub.
