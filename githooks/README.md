# Git hooks

Sau mỗi commit, tự động push lên mọi remote.

**Cài đặt (chạy 1 lần trong repo):**

```bash
cp githooks/post-commit .git/hooks/post-commit
chmod +x .git/hooks/post-commit
```

Windows (PowerShell):

```powershell
Copy-Item githooks\post-commit .git\hooks\post-commit -Force
```
