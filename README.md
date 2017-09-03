# gin-csrf
Cookie-to-header csrf for gin with max usage feature.

# Usage
```go
router := gin.Default()
options := csrf.DefaultOptions()
options.MaxUsage = 10
options.MaxAge = 15 * 60
router.Use(csrf.Csrf(options))
```
