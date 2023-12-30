# DatingApp

1.Pokrenemo aplikaciju kroz terminal i instaliramo sve dodatke koji su nam potrebni, pokrenemo aplikaciju u editoru te pobrišemo i prilagodimo sve postavke koje će nam koristiti za izradu projekta

2.Otvorimo folder Entities u koji otvorimo novi file AppUser gdje postavimo konstruktor

```c#
public class AppUser
{
   public int Id { get; set; }  
    public string UserName { get; set; }
}
```

3.Otvorimo novi folder u folderu API te kreiramo file DataContext koji će naslijediti DbContext *(DbContext  je ključni dio Entity Frameworka, koji je ORM (Object-Relational Mapping) alat za rad s bazama podataka u .NET okruženju. DbContext predstavlja "session" s bazom podataka i omogućuje vam izvršavanje upita, promjena i ažuriranje podataka u bazi podataka pomoću objekata u vašem .NET programu.)*

```c#
public class DataContext : DbContext
{
    public DataContext(DbContextOptions options) : base(options)
    {
    }

    public DbSet<AppUser> Users { get; set; }
}
```

4.Odemo u klasu Program.cs te definiramo vezu za DbContext odnosno dodamo service

```c#
builder.Services.AddDbContext<DataContext>(opt =>
{
    opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));

});
```

"*Ovdje se specificira pružatelj baze podataka koji će DbContext koristiti, u ovom slučaju, Sqlite. Također se konfigurira veza prema bazi podataka putem metode UseSqlite koja prima connection string kao argument. Connection string se obično dohvaća iz konfiguracije aplikacije, a u ovom slučaju koristi se builder.Configuration.GetConnectionString("DefaultConnection")*"

## Kreiranje Connection stringa

Da bi postavili Conection string ići ćemo u file appsettings.Development.json

![Alt text](<Screenshot 2023-12-29 143503.png>)

![Alt text](<Screenshot 2023-12-29 144323.png>)

Nakon postavljanja conection stringa mozemo otvoriti migracije ali prije toga će nam trebati alat *dotnet-ef*
koji nemožemo instalirati preko nuget package već na drugi način

![Alt text](dotnet-ef.png)

kopirat ćemo komandu i zaustaviti app u terminalu te je paste komandu u terminal
nakon što smo instalirali dotnet-ef možemo dodati novu migraciju naredbom u terminalu *dotnet ef migrations add InitialCreate -o Data/Migrations*

![Alt text](<Screenshot 2023-12-29 150535-1.png>)
*dobili smo novi folder Migrations unutar Data foldera kao što smo konkretizirali u naredbi prije Data/Migrations*

unutar foldera migrations imamo tri file-a, jedan od njih je _initialCreate.cs i u njemu se nalazi kod za kreiranje tabele pomoću migracije koju je vsCode sam generirao

```c#
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace API.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    UserName = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}

```

ako u terminalu ukucamo *dotnet ef database -h* možemo vidjeti da imamo dvije opcije što možemo raditi sa bazom: drop i update

![Alt text](<Screenshot 2023-12-29 152015.png>)

Otići ćemo na bazu i dodati ručno par imena i id za svrhu daljnjeg developmenta.. SQLITE EXPLORER/datingapp.db/Users => New Query [insert]

![Alt text](<Screenshot 2023-12-30 094231.png>)

5.Dodavanje UsersControllera

```c#

using API.Data;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

[ApiController] // this is an API controller
[Route("api/[controller]")] // api/users

public class UsersController : ControllerBase
{
     private readonly DataContext _context;

    public UsersController(DataContext context)
    {
        _context = context;
    }
}

```

Kad smo dodali controller  treba nam [HttpGet] kojom ćemo ući u naš kontekst i s kojom ćemo vratiti IEnumerable imenom AppUser i s kojom ćemo iz dataContexta(tablice) vratiti Usera i nakon toga istu stvar s id-em

```c#
 [HttpGet]

    public <ActionResult<IEnumerable<AppUser>>GetUsers()
    {
        var users = _context.Users.ToList();
        return users;
    }

    [HttpGet("{id}")] // api/users/2

    public  <ActionResult<AppUser>GetUser(int id)
    {
        return  _context.Users.Find(id);
        
    }

```

Provjerit ćemo u localhostu ili aplikaciji Postman dali ruta vodi do baze preko controllera.

6.Prebacivanje sinkronog koda u asinkroni

Prebacivanje sinkronog koda u asinkroni oblik često se radi kako bi se poboljšala reaktivnost i performanse aplikacija, posebno u situacijama gdje su prisutne operacije koje traju dulje vrijeme, kao što su pristupi bazama podataka, mrežni pozivi ili čekanje na vanjske resurse.

```c#
 [HttpGet]

    public async Task<ActionResult<IEnumerable<AppUser>>>GetUsers()
    {
        var users = await _context.Users.ToListAsync();
        return users;
    }

    [HttpGet("{id}")] // api/users/2

    public async Task<ActionResult<AppUser>>GetUser(int id)
    {
        return await _context.Users.FindAsync(id);    
    } 
```
7.Snimanje našeg koda u Source control


