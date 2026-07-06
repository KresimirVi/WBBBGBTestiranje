# MoBanka — C#

Namjerno ranjiva bankarska web aplikacija za demonstraciju sigurnosnog testiranja.

## Tehnologije

| Sloj | Tehnologija |
|------|-------------|
| Backend | C# ASP.NET Core 8 (Minimal API) |
| Baza podataka | SQLite (Microsoft.Data.Sqlite) |
| Frontend | React 18 (CDN) |

## Pokretanje

### Preduvjeti
- .NET SDK 8.0 — preuzmi s https://dotnet.microsoft.com/download

### Naredbe
```
cd mobanka-csharp
dotnet run
```
Otvori browser → http://localhost:5000

### Demo korisnici
- marko / marko123
- ana / ana456
- admin / admin123


## Ranjivosti

| # | Ranjivost | Lokacija u kodu |
|---|-----------|-----------------|
| 1 | SQL Injection | Program.cs → MapGet("/api/search") |
| 2 | IDOR | Program.cs → MapGet("/api/account/{id}") |
| 3 | CSRF | Program.cs → MapPost("/api/transfer") |
| 4 | Business Logic | Program.cs → MapPost("/api/transfer") |
| 5 | Broken Access Control | Program.cs → MapGet("/api/admin") |
| 6 | Plaintext lozinke + no rate limit | Program.cs → MapPost("/api/login") + InitDb() |
