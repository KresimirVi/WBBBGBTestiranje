using Microsoft.Data.Sqlite;
using System.Text.Json.Serialization;

const string DB = "mobanka.db";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(o =>
{
    o.Cookie.HttpOnly    = true;
    o.Cookie.IsEssential = true;
    o.IdleTimeout        = TimeSpan.FromHours(2);
});
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.PropertyNameCaseInsensitive = true);

var app = builder.Build();

app.UseSession();
app.UseDefaultFiles();
app.UseStaticFiles();

InitDb();

SqliteConnection Conn()
{
    var conn = new SqliteConnection($"Data Source={DB}");
    conn.Open();
    return conn;
}

bool LoggedIn(HttpContext ctx) =>
    ctx.Session.GetInt32("UserId") != null;

IResult Unauth() =>
    Results.Json(new { error = "Unauthorized" }, statusCode: 401);

app.MapGet("/api/me", (HttpContext ctx) =>
{
    var userId = ctx.Session.GetInt32("UserId");
    if (userId == null) return Results.Ok(new { user = (object?)null });

    return Results.Ok(new
    {
        user = new
        {
            id        = userId,
            username  = ctx.Session.GetString("Username"),
            full_name = ctx.Session.GetString("FullName"),
            role      = ctx.Session.GetString("Role")
        }
    });
});

app.MapPost("/api/login", (LoginReq req, HttpContext ctx) =>
{
    var username = req.Username?.Trim() ?? "";
    var password = req.Password ?? "";

    // ════════════════════════════════════════════════════════════════════
    // RANJIVOST #6 — Plaintext lozinke + nema rate limitinga
    // ════════════════════════════════════════════════════════════════════
    // Black box: opetovano slanje pogrešnih lozinki za isto korisničko
    // ime ne dovodi ni do kakvog usporavanja, blokade ili upozorenja.
    // (ispravan kod)
    //   var hash = BCrypt.Net.BCrypt.HashPassword(password);
    //   builder.Services.AddRateLimiter(o => { /* limiter po IP-u/korisniku */ });
    //
    // Grey box: uz poznavanje da /api/login prima username i password u
    // JSON tijelu, ponovljeni zahtjevi prema istom korisniku potvrđuju da
    // ne postoji ograničenje broja pokušaja.
    // (ispravan kod)
    //   var hash = BCrypt.Net.BCrypt.HashPassword(password);
    //   builder.Services.AddRateLimiter(o => { /* limiter po IP-u/korisniku */ });
    //
    // White box: pregledom baze i koda vidljivo je da se lozinke
    // spremaju i uspoređuju kao čisti tekst (bez hashiranja), te da ne
    // postoji brojač neuspjelih pokušaja prijave.
    // (ispravan kod)
    //   var hash = BCrypt.Net.BCrypt.HashPassword(password);
    //   // pri prijavi: BCrypt.Net.BCrypt.Verify(password, user.PasswordHash)
    //   builder.Services.AddRateLimiter(o => { /* limiter po IP-u/korisniku */ });
    // ════════════════════════════════════════════════════════════════════
    using var conn = Conn();
    var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM users WHERE username = @u AND password = @p";
    cmd.Parameters.AddWithValue("@u", username);
    cmd.Parameters.AddWithValue("@p", password);

    using var r = cmd.ExecuteReader();
    if (!r.Read())
        return Results.Ok(new { success = false, error = "Neispravno korisničko ime ili lozinka." });

    var id       = (int)(long)r["id"];
    var uname    = (string)r["username"];
    var fullName = (string)r["full_name"];
    var role     = (string)r["role"];
    r.Close();

    ctx.Session.SetInt32("UserId",    id);
    ctx.Session.SetString("Username", uname);
    ctx.Session.SetString("FullName", fullName);
    ctx.Session.SetString("Role",     role);

    return Results.Ok(new
    {
        success = true,
        user    = new { id, username = uname, full_name = fullName, role }
    });
});

app.MapPost("/api/logout", (HttpContext ctx) =>
{
    ctx.Session.Clear();
    return Results.Ok(new { success = true });
});

app.MapPost("/api/register", (RegisterReq req, HttpContext ctx) =>
{
    var username = req.Username?.Trim() ?? "";
    var password = req.Password ?? "";
    var fullName = req.FullName?.Trim() ?? "";
    var email    = req.Email?.Trim() ?? "";

    if (string.IsNullOrEmpty(username))
        return Results.Ok(new { success = false, error = "Korisničko ime je obavezno." });
    if (string.IsNullOrEmpty(password))
        return Results.Ok(new { success = false, error = "Lozinka je obavezna." });
    if (string.IsNullOrEmpty(fullName))
        return Results.Ok(new { success = false, error = "Puno ime je obavezno." });
    if (string.IsNullOrEmpty(email))
        return Results.Ok(new { success = false, error = "Email je obavezan." });

    using var conn = Conn();

    var cmdCheck = conn.CreateCommand();
    cmdCheck.CommandText = "SELECT COUNT(*) FROM users WHERE username = @u";
    cmdCheck.Parameters.AddWithValue("@u", username);
    var exists = (long)(cmdCheck.ExecuteScalar() ?? 0L);
    if (exists > 0)
        return Results.Ok(new { success = false, error = "Korisničko ime već postoji." });

    var cmdIns = conn.CreateCommand();
    cmdIns.CommandText =
        "INSERT INTO users (username, password, full_name, email, role) " +
        "VALUES (@u, @p, @fn, @e, 'user')";
    cmdIns.Parameters.AddWithValue("@u",  username);
    cmdIns.Parameters.AddWithValue("@p",  password);
    cmdIns.Parameters.AddWithValue("@fn", fullName);
    cmdIns.Parameters.AddWithValue("@e",  email);
    cmdIns.ExecuteNonQuery();

    var cmdId = conn.CreateCommand();
    cmdId.CommandText = "SELECT last_insert_rowid()";
    var newId = (int)(long)(cmdId.ExecuteScalar() ?? 0L);

    var cmdAcc = conn.CreateCommand();
    cmdAcc.CommandText =
        "INSERT INTO accounts (user_id, account_type, iban, balance) " +
        "VALUES (@uid, 'Tekući račun', @iban, 0.00)";
    cmdAcc.Parameters.AddWithValue("@uid",  newId);
    cmdAcc.Parameters.AddWithValue("@iban", $"12 2340 0091 {newId:D4} 0000 0");
    cmdAcc.ExecuteNonQuery();

    ctx.Session.SetInt32("UserId",    newId);
    ctx.Session.SetString("Username", username);
    ctx.Session.SetString("FullName", fullName);
    ctx.Session.SetString("Role",     "user");

    return Results.Ok(new
    {
        success = true,
        user    = new { id = newId, username, full_name = fullName, role = "user" }
    });
});

app.MapGet("/api/dashboard", (HttpContext ctx) =>
{
    if (!LoggedIn(ctx)) return Unauth();
    var userId = ctx.Session.GetInt32("UserId")!.Value;

    using var conn = Conn();

    var cmdA = conn.CreateCommand();
    cmdA.CommandText = "SELECT * FROM accounts WHERE user_id = @uid";
    cmdA.Parameters.AddWithValue("@uid", userId);

    var accounts   = new List<object>();
    var accountIds = new List<int>();

    using var rA = cmdA.ExecuteReader();
    while (rA.Read())
    {
        var accId = (int)(long)rA["id"];
        accountIds.Add(accId);
        accounts.Add(new
        {
            id           = accId,
            user_id      = (int)(long)rA["user_id"],
            account_type = (string)rA["account_type"],
            iban         = (string)rA["iban"],
            balance      = (double)rA["balance"]
        });
    }
    rA.Close();

    var transactions = new List<object>();
    if (accountIds.Count > 0)
    {
        var ph   = string.Join(",", accountIds.Select((_, i) => $"@p{i}"));
        var cmdT = conn.CreateCommand();
        cmdT.CommandText =
            $"SELECT t.*, a.account_type FROM transactions t " +
            $"JOIN accounts a ON t.account_id = a.id " +
            $"WHERE t.account_id IN ({ph}) " +
            $"ORDER BY t.created_at DESC LIMIT 20";

        for (int i = 0; i < accountIds.Count; i++)
            cmdT.Parameters.AddWithValue($"@p{i}", accountIds[i]);

        using var rT = cmdT.ExecuteReader();
        while (rT.Read())
        {
            transactions.Add(new
            {
                id           = (int)(long)rT["id"],
                account_id   = (int)(long)rT["account_id"],
                description  = (string)rT["description"],
                amount       = (double)rT["amount"],
                created_at   = (string)rT["created_at"],
                account_type = (string)rT["account_type"]
            });
        }
    }

    return Results.Ok(new { accounts, transactions });
});

app.MapGet("/api/account/{id:int}", (int id, HttpContext ctx) =>
{
    if (!LoggedIn(ctx)) return Unauth();
    var userId = ctx.Session.GetInt32("UserId")!.Value;

    using var conn = Conn();
    var cmd = conn.CreateCommand();

    // ════════════════════════════════════════════════════════════════════
    // RANJIVOST #2 — IDOR (Insecure Direct Object Reference)
    // ════════════════════════════════════════════════════════════════════
    // Black box: promjenom identifikatora računa u zahtjevu, bez uvida u
    // kod, dobivaju se podaci računa koji ne pripada prijavljenom korisniku.
    // (ispravan kod)
    //   cmd.CommandText = "SELECT a.*, u.full_name AS owner_name, " +
    //       "u.username AS owner_username FROM accounts a " +
    //       "JOIN users u ON a.user_id = u.id " +
    //       "WHERE a.id = @id AND a.user_id = @uid";
    //   cmd.Parameters.AddWithValue("@id",  id);
    //   cmd.Parameters.AddWithValue("@uid", userId);
    //
    // Grey box: uz poznavanje da endpoint /api/account/{id} prima
    // identifikator računa, ciljano testiranje potvrđuje da vlasništvo
    // nad računom nije provjereno.
    // (ispravan kod)
    //   cmd.CommandText = "SELECT a.*, u.full_name AS owner_name, " +
    //       "u.username AS owner_username FROM accounts a " +
    //       "JOIN users u ON a.user_id = u.id " +
    //       "WHERE a.id = @id AND a.user_id = @uid";
    //   cmd.Parameters.AddWithValue("@id",  id);
    //   cmd.Parameters.AddWithValue("@uid", userId);
    //
    // White box: pregledom koda vidljivo je da SQL upit dohvaća račun
    // samo po identifikatoru, bez provjere da taj račun pripada
    // trenutno prijavljenom korisniku (user_id).
    // (ispravan kod)
    //   cmd.CommandText = "SELECT a.*, u.full_name AS owner_name, " +
    //       "u.username AS owner_username FROM accounts a " +
    //       "JOIN users u ON a.user_id = u.id " +
    //       "WHERE a.id = @id AND a.user_id = @uid";
    //   cmd.Parameters.AddWithValue("@id",  id);
    //   cmd.Parameters.AddWithValue("@uid", userId);
    // ════════════════════════════════════════════════════════════════════
    cmd.CommandText =
        "SELECT a.*, u.full_name AS owner_name, u.username AS owner_username " +
        "FROM accounts a JOIN users u ON a.user_id = u.id WHERE a.id = @id";
    cmd.Parameters.AddWithValue("@id", id);

    using var rA = cmd.ExecuteReader();
    if (!rA.Read())
        return Results.NotFound(new { error = "Račun nije pronađen." });

    var accUserId = (int)(long)rA["user_id"];
    var account   = new
    {
        id             = (int)(long)rA["id"],
        user_id        = accUserId,
        account_type   = (string)rA["account_type"],
        iban           = (string)rA["iban"],
        balance        = (double)rA["balance"],
        owner_name     = (string)rA["owner_name"],
        owner_username = (string)rA["owner_username"],
        is_own         = accUserId == userId
    };
    rA.Close();

    var cmdT = conn.CreateCommand();
    cmdT.CommandText =
        "SELECT * FROM transactions WHERE account_id = @id ORDER BY created_at DESC";
    cmdT.Parameters.AddWithValue("@id", id);

    var txs = new List<object>();
    using var rT = cmdT.ExecuteReader();
    while (rT.Read())
    {
        txs.Add(new
        {
            id          = (int)(long)rT["id"],
            account_id  = (int)(long)rT["account_id"],
            description = (string)rT["description"],
            amount      = (double)rT["amount"],
            created_at  = (string)rT["created_at"]
        });
    }

    return Results.Ok(new { account, transactions = txs });
});

app.MapPost("/api/transfer", (TransferReq req, HttpContext ctx) =>
{
    if (!LoggedIn(ctx)) return Unauth();
    var userId = ctx.Session.GetInt32("UserId")!.Value;

    // ════════════════════════════════════════════════════════════════════
    // RANJIVOST #3 — CSRF (Cross-Site Request Forgery)
    // ════════════════════════════════════════════════════════════════════
    // Black box: zahtjev poslan prema aplikaciji u ime prijavljenog
    // korisnika, ali pokrenut s druge stranice, biva prihvaćen bez
    // ikakve dodatne potvrde.
    // (ispravan kod)
    //   builder.Services.AddAntiforgery();
    //   app.UseAntiforgery();
    //
    // Grey box: uz poznavanje da /api/transfer prihvaća POST zahtjev s
    // podacima o transferu, presretanjem prometa se potvrđuje da ne
    // postoji token protiv krivotvorenja zahtjeva.
    // (ispravan kod)
    //   builder.Services.AddAntiforgery();
    //   app.UseAntiforgery();
    //
    // White box: pregledom koda vidljivo je da ruta ne provjerava
    // anti-forgery token niti postoji ikakva zaštita od CSRF-a.
    // (ispravan kod)
    //   builder.Services.AddAntiforgery();
    //   app.UseAntiforgery();
    //   // za API pristup, alternativno: provjera CSRF tokena iz sesije
    //   // usporedbom s tokenom poslanim u zahtjevu
    // ════════════════════════════════════════════════════════════════════

    var fromId = req.FromAccount ?? 0;
    var iban   = req.Iban?.Trim() ?? "";
    var amount = req.Amount ?? 0.0;
    var desc   = string.IsNullOrWhiteSpace(req.Description) ? "Transfer" : req.Description.Trim();

    if (string.IsNullOrEmpty(iban))
        return Results.Ok(new { error = "IBAN primatelja je obavezan." });

    using var conn = Conn();
    var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM accounts WHERE id = @id AND user_id = @uid";
    cmd.Parameters.AddWithValue("@id",  fromId);
    cmd.Parameters.AddWithValue("@uid", userId);

    using var r = cmd.ExecuteReader();
    if (!r.Read())
        return Results.Ok(new { error = "Nevažeći izvorni račun." });

    var balance = (double)r["balance"];
    r.Close();

    // ════════════════════════════════════════════════════════════════════
    // RANJIVOST #4 — Business Logic (negativan iznos)
    // ════════════════════════════════════════════════════════════════════
    // Black box: unosom negativnog iznosa u polje za transfer, stanje
    // računa se poveća umjesto da se smanji.
    // (ispravan kod)
    //   if (amount <= 0)
    //       return Results.Ok(new { error = "Iznos mora biti veći od nule." });
    //
    // Grey box: uz poznavanje da /api/transfer prima numeričko polje
    // amount, slanjem negativne vrijednosti potvrđuje se da poslužitelj
    // ne provjerava predznak iznosa.
    // (ispravan kod)
    //   if (amount <= 0)
    //       return Results.Ok(new { error = "Iznos mora biti veći od nule." });
    //
    // White box: pregledom koda vidljivo je da ne postoji provjera je li
    // amount pozitivan prije izračuna novog stanja računa.
    // (ispravan kod)
    //   if (amount <= 0)
    //       return Results.Ok(new { error = "Iznos mora biti veći od nule." });
    // ════════════════════════════════════════════════════════════════════
    var newBalance = balance - amount;

    var cmdU = conn.CreateCommand();
    cmdU.CommandText = "UPDATE accounts SET balance = @bal WHERE id = @id";
    cmdU.Parameters.AddWithValue("@bal", newBalance);
    cmdU.Parameters.AddWithValue("@id",  fromId);
    cmdU.ExecuteNonQuery();

    var cmdI = conn.CreateCommand();
    cmdI.CommandText =
        "INSERT INTO transactions (account_id, description, amount, created_at) " +
        "VALUES (@aid, @desc, @amt, datetime('now'))";
    cmdI.Parameters.AddWithValue("@aid",  fromId);
    cmdI.Parameters.AddWithValue("@desc", $"{desc} -> {iban}");
    cmdI.Parameters.AddWithValue("@amt",  -amount);
    cmdI.ExecuteNonQuery();

    return Results.Ok(new
    {
        success = true,
        message = $"Uplata od {amount:F2} € uspješno izvršena na {iban}."
    });
});

app.MapGet("/api/search", (string? q, HttpContext ctx) =>
{
    if (!LoggedIn(ctx)) return Unauth();
    if (string.IsNullOrWhiteSpace(q))
        return Results.Ok(new { results = Array.Empty<object>() });

    using var conn = Conn();
    var cmd = conn.CreateCommand();

    // ════════════════════════════════════════════════════════════════════
    // RANJIVOST #1 — SQL Injection
    // ════════════════════════════════════════════════════════════════════
    // Black box: unosom posebnih znakova u polje pretrage, bez uvida u
    // kod, mijenja se ponašanje upita i vraćaju podaci koji ne pripadaju
    // prijavljenom korisniku.
    // (ispravan kod)
    //   cmd.CommandText = "... WHERE t.description LIKE @q";
    //   cmd.Parameters.AddWithValue("@q", $"%{q}%");
    //
    // Grey box: uz poznavanje da /api/search prihvaća parametar q i
    // prosljeđuje ga u SQL upit, ciljanim testiranjem parametra potvrđuje
    // se izostanak parametrizacije.
    // (ispravan kod)
    //   cmd.CommandText = "... WHERE t.description LIKE @q";
    //   cmd.Parameters.AddWithValue("@q", $"%{q}%");
    //
    // White box: pregledom koda vidljivo je da se parametar q izravno
    // umeće u SQL naredbu putem interpolacije stringa, umjesto da se
    // koristi parametrizirani upit.
    // (ispravan kod)
    //   cmd.CommandText = "... WHERE t.description LIKE @q";
    //   cmd.Parameters.AddWithValue("@q", $"%{q}%");
    // ════════════════════════════════════════════════════════════════════
    cmd.CommandText =
        "SELECT t.id, t.description, t.amount, t.created_at, a.account_type, u.full_name " +
        "FROM transactions t " +
        "JOIN accounts a ON t.account_id = a.id " +
        "JOIN users u ON a.user_id = u.id " +
        $"WHERE t.description LIKE '%{q}%'";

    try
    {
        using var r       = cmd.ExecuteReader();
        var results = new List<object>();
        while (r.Read())
        {
            results.Add(new
            {
                id           = r.IsDBNull(0) ? 0 : (int)(long)r.GetValue(0),
                description  = r.IsDBNull(1) ? "" : r.GetValue(1)?.ToString() ?? "",
                amount       = r.GetValue(2),
                created_at   = r.IsDBNull(3) ? "" : r.GetValue(3)?.ToString() ?? "",
                account_type = r.IsDBNull(4) ? "" : r.GetValue(4)?.ToString() ?? "",
                full_name    = r.IsDBNull(5) ? "" : r.GetValue(5)?.ToString() ?? ""
            });
        }
        return Results.Ok(new { results });
    }
    catch (Exception ex)
    {
        return Results.Ok(new { results = Array.Empty<object>(), error = ex.Message });
    }
});

app.MapGet("/api/admin", (HttpContext ctx) =>
{
    if (!LoggedIn(ctx)) return Unauth();

    // ════════════════════════════════════════════════════════════════════
    // RANJIVOST #5 — Broken Access Control
    // ════════════════════════════════════════════════════════════════════
    // Black box: prijavom kao obični korisnik i otvaranjem administratorske
    // rute dobiva se pristup podacima i lozinkama svih korisnika.
    // (ispravan kod)
    //   if (ctx.Session.GetString("Role") != "admin")
    //       return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    //
    // Grey box: uz poznavanje postojanja rute /api/admin, izravan zahtjev
    // bilo kojim prijavljenim korisnikom potvrđuje da provjera uloge
    // ne postoji.
    // (ispravan kod)
    //   if (ctx.Session.GetString("Role") != "admin")
    //       return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    //
    // White box: pregledom koda vidljivo je da ruta provjerava samo je
    // li korisnik prijavljen (LoggedIn), a ne i njegovu ulogu (role).
    // (ispravan kod)
    //   if (ctx.Session.GetString("Role") != "admin")
    //       return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    // ════════════════════════════════════════════════════════════════════

    using var conn = Conn();

    var cmdU  = conn.CreateCommand();
    cmdU.CommandText = "SELECT * FROM users";
    var users = new List<object>();
    using var rU = cmdU.ExecuteReader();
    while (rU.Read())
    {
        users.Add(new
        {
            id        = (int)(long)rU["id"],
            username  = (string)rU["username"],
            password  = (string)rU["password"],
            full_name = (string)rU["full_name"],
            email     = (string)rU["email"],
            role      = (string)rU["role"]
        });
    }
    rU.Close();

    var cmdA     = conn.CreateCommand();
    cmdA.CommandText =
        "SELECT a.*, u.full_name FROM accounts a JOIN users u ON a.user_id = u.id";
    var accounts = new List<object>();
    using var rA = cmdA.ExecuteReader();
    while (rA.Read())
    {
        accounts.Add(new
        {
            id           = (int)(long)rA["id"],
            user_id      = (int)(long)rA["user_id"],
            account_type = (string)rA["account_type"],
            iban         = (string)rA["iban"],
            balance      = (double)rA["balance"],
            full_name    = (string)rA["full_name"]
        });
    }

    return Results.Ok(new { users, accounts });
});

app.MapFallbackToFile("index.html");

app.Run("http://localhost:5000");

void InitDb()
{
    using var conn = new SqliteConnection($"Data Source={DB}");
    conn.Open();

    var cmd = conn.CreateCommand();
    cmd.CommandText = @"
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT NOT NULL UNIQUE,
            password  TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email     TEXT NOT NULL,
            role      TEXT NOT NULL DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            account_type TEXT NOT NULL,
            iban         TEXT NOT NULL,
            balance      REAL NOT NULL DEFAULT 0.0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id  INTEGER NOT NULL,
            description TEXT NOT NULL,
            amount      REAL NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );
    ";
    cmd.ExecuteNonQuery();

    cmd.CommandText = "UPDATE accounts SET account_type = 'Tekući račun' WHERE account_type LIKE 'Tekuc%'";
    cmd.ExecuteNonQuery();
    cmd.CommandText = "UPDATE accounts SET account_type = 'Štedni račun' WHERE account_type LIKE 'Stedn%'";
    cmd.ExecuteNonQuery();

    cmd.CommandText = "SELECT COUNT(*) FROM users";
    var count = (long)(cmd.ExecuteScalar() ?? 0L);
    if (count > 0) return;

    void Run(string sql) { cmd.CommandText = sql; cmd.ExecuteNonQuery(); }

    Run("INSERT INTO users (username,password,full_name,email,role) VALUES ('ivan','ivan123','Ivan Perić','ivan@mail.com','user')");
    Run("INSERT INTO users (username,password,full_name,email,role) VALUES ('marko','marko123','Marko Horvat','marko@mail.com','user')");
    Run("INSERT INTO users (username,password,full_name,email,role) VALUES ('luka','luka123','Luka Kovačević','luka@mail.com','user')");
    Run("INSERT INTO users (username,password,full_name,email,role) VALUES ('ana','ana456','Ana Kovač','ana@mail.com','user')");
    Run("INSERT INTO users (username,password,full_name,email,role) VALUES ('iva','iva123','Iva Babić','iva@mail.com','user')");
    Run("INSERT INTO users (username,password,full_name,email,role) VALUES ('danijel','danijel123','Danijel Matić','danijel@mail.com','user')");
    Run("INSERT INTO users (username,password,full_name,email,role) VALUES ('lara','lara123','Lara Šimić','lara@mail.com','user')");
    Run("INSERT INTO users (username,password,full_name,email,role) VALUES ('rozalija','rozalija123','Rozalija Blažević','rozalija@mail.com','user')");

    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (1,'Tekući račun','12 2340 0091 1001 2345 6',3240.00)");
    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (1,'Štedni račun','12 2340 0091 1001 9876 5',11500.00)");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (1,'Plaća - Acme d.o.o.',2800.00,'2026-05-01')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (1,'Konzum d.o.o.',-38.50,'2026-05-10')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (1,'Stanarina',-650.00,'2026-05-02')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (2,'Kamate',57.50,'2026-04-01')");

    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (2,'Tekući račun','12 2340 0091 2001 3456 7',4820.00)");
    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (2,'Štedni račun','12 2340 0091 2001 9876 5',12500.00)");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (3,'Plaća - Beta d.o.o.',3200.00,'2026-05-01')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (3,'HEP - Struja',-87.50,'2026-04-28')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (3,'Netflix',-15.99,'2026-05-05')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (4,'Kamate',62.50,'2026-04-01')");

    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (3,'Tekući račun','12 2340 0091 3001 4567 8',8920.00)");
    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (3,'Štedni račun','12 2340 0091 3001 1111 0',31500.00)");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (5,'Plaća - Tech Solutions',4800.00,'2026-05-01')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (5,'Amazon',-124.99,'2026-05-09')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (5,'Stanarina',-900.00,'2026-05-03')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (6,'Kamate',157.50,'2026-04-01')");

    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (4,'Tekući račun','12 2340 0091 4001 2222 3',8340.00)");
    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (4,'Štedni račun','12 2340 0091 4001 5555 6',31200.00)");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (7,'Plaća - Gamma d.o.o.',3500.00,'2026-05-01')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (7,'Najam stana',-850.00,'2026-05-02')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (7,'DM Drogerie',-55.20,'2026-05-14')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (8,'Kamate',156.00,'2026-04-01')");

    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (5,'Tekući račun','12 2340 0091 5001 3333 4',2150.00)");
    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (5,'Štedni račun','12 2340 0091 5001 7777 8',7800.00)");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (9,'Plaća - Art Studio',2200.00,'2026-05-01')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (9,'Spar',-44.90,'2026-05-08')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (9,'Spotify',-9.99,'2026-05-05')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (10,'Kamate',39.00,'2026-04-01')");

    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (6,'Tekući račun','12 2340 0091 6001 4444 5',15600.00)");
    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (6,'Štedni račun','12 2340 0091 6001 8888 9',68000.00)");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (11,'Plaća - Sigma d.d.',6500.00,'2026-05-01')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (11,'Kredit - rata',-1500.00,'2026-05-03')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (11,'Kaufland',-97.30,'2026-05-15')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (12,'Kamate',340.00,'2026-04-01')");

    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (7,'Tekući račun','12 2340 0091 7001 5555 6',1890.00)");
    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (7,'Štedni račun','12 2340 0091 7001 2222 3',4200.00)");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (13,'Plaća - Studio Lara',1800.00,'2026-05-01')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (13,'Kirija',-600.00,'2026-05-02')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (13,'Lidl',-32.80,'2026-05-11')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (14,'Kamate',21.00,'2026-04-01')");

    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (8,'Tekući račun','12 2340 0091 8001 6666 7',6430.00)");
    Run("INSERT INTO accounts (user_id,account_type,iban,balance) VALUES (8,'Štedni račun','12 2340 0091 8001 3333 4',19750.00)");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (15,'Plaća - Delta d.o.o.',4200.00,'2026-05-01')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (15,'Gorivo - INA',-80.00,'2026-05-12')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (15,'Pretplata - HBO',-13.99,'2026-05-06')");
    Run("INSERT INTO transactions (account_id,description,amount,created_at) VALUES (16,'Kamate',98.75,'2026-04-01')");
}

record LoginReq(
    [property: JsonPropertyName("username")] string? Username,
    [property: JsonPropertyName("password")] string? Password
);

record TransferReq(
    [property: JsonPropertyName("from_account")] int?    FromAccount,
    [property: JsonPropertyName("iban")]          string? Iban,
    [property: JsonPropertyName("amount")]        double? Amount,
    [property: JsonPropertyName("description")]   string? Description
);

record RegisterReq(
    [property: JsonPropertyName("username")]  string? Username,
    [property: JsonPropertyName("password")]  string? Password,
    [property: JsonPropertyName("full_name")] string? FullName,
    [property: JsonPropertyName("email")]     string? Email
);
