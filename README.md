# MoBanka — C# verzija

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

### Demo kredencijali
- marko / marko123
- ana / ana456
- admin / admin123

## Otvaranje u IDE

### Visual Studio 2022
1. File → Open → Project/Solution
2. Odaberi MoBanka.csproj
3. Klikni zeleni gumb Run (F5)

### Visual Studio Code
1. Instaliraj C# Dev Kit ekstenziju
2. File → Open Folder → odaberi mobanka-csharp
3. Terminal → New Terminal → dotnet run

## Ranjivosti (za testiranje — vidi MoBanka_Ranjivosti.docx)

| # | Ranjivost | Lokacija u kodu |
|---|-----------|-----------------|
| 1 | SQL Injection | Program.cs → MapGet("/api/search") |
| 2 | IDOR | Program.cs → MapGet("/api/account/{id}") |
| 3 | CSRF | Program.cs → MapPost("/api/transfer") |
| 4 | Business Logic | Program.cs → MapPost("/api/transfer") |
| 5 | Broken Access Control | Program.cs → MapGet("/api/admin") |
| 6 | Plaintext lozinke + no rate limit | Program.cs → MapPost("/api/login") + InitDb() |
