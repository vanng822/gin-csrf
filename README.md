# gin-csrf
Cookie-to-header csrf for gin

# Usage
```go
router := gin.Default()
router.Use(csrf.Csrf(100, true))
```
