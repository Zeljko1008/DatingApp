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

Moramo instalirati git i napraviti git hub profil ako već nismo

Kliknemo na Git hubu profilnu sliku s desne strane ekrana pa na settings, <>Development settings, Personal aces token, new classic token, zatim označimo polja  koja želimo i generiramo
Obavezno snimiti personal aces token now, jer poslije neće biti moguće
![Alt text](<Screenshot 2023-12-30 113136-1.png>)

ući u vscode u comand line dati naredbu
`git init` međutim ako bi commitali u ovom trenutku aplikacija bi poslala puno nepotrebnih stvari (preko 100 file-ova ) zato ćemo ipak dati naredbu `dotnet new gitignore` te ćemo  neke filove koje ne želimo objaviti javno kliknuti desnim klikom i dodati u git ignore
isto tako i appsettings.json file
zatim kliknemo na + znak kraj changes u source controlu dati ćemo ime repositoriu i klik na COMMIT

Prije nego objavimo branch na gitu kreirat ćemo new repository na gitu dati mu ime i kreirat ćemo ga nakon čega će se pojaviti daljnje instrukcije

`git branch -M main` komanda za mjenjanje imena branch-a

`git remote add origin https://github.com/Zeljko1008/DatingApp.git` komanda za kreiranje novog direktorija na git hubu nakon koje možemo u vscodu u SOURCE CONTROL stisnuti dugme *Publish Branch*
Odemo u Git Hub , refresh i vidimo naš app

8.Creating Angular application

Provjerit ćemo koju verziju Angulara imamo instaliranu, zatim Angular CLI i node js te dali su stabilne i kompatibilne 
zatim ćemo kreirati Angular aplikacijom komandom u terminalu `ng new client` s tim da ćemo obratiti pozornost u kojem smo folderu prije toga

sa `ng serve` pokrećemo našu angular aplikaciju 
iz app.components.html brišemo sve

8.Making http request in Angular

Cilj trenutni je da oživimo kostur tako da očitamo bazu u našem angular appu.

- prvi korak je da odemo u app.module.ts i da dodamo nešto što će povezati naš client (angular) sa API serverom. prvo ćemo ručno unesti HttpClient module

  ![Alt text](<Screenshot 2023-12-30 172608.png>)

- zatim ćemo otići na app.component.ts i želimo uvesti podatak iz app.module.ts

- klasi AppComponent implementira OnInit sučelje, što znači da mora pružiti implementaciju ngOnInit metode. Kada se komponenta inicijalizira, Angular će automatski pozvati ovu metodu. To je dobro mjesto za postavljanje inicijalizacijskih zadataka koji trebaju biti obavljeni prije nego što se komponenta počne koristiti.

- kreirat ćemo konstruktor u klasi AppComponent tako da kad se izvršava ta komponenta se izvršava i kod u konstruktoru

```ts
export class AppComponent implements OnInit{

  title: string  = 'Dating App';
  users: any; // Add this

  constructor( private http: HttpClient) {}
  ngOnInit(): void
  {
    this.http.get('https://localhost:5001/api/users').subscribe({
      next : response => this.users = response,
      error: error => console.log('error'),
      complete: () => console.log('complete')
    })
  }
```
- s ovim kodom želimo dohvatiti http na ovoj lokaciji `https://localhost:5001/api/users`
a vratit će nam se *Observable* (*U Angularu, Observable je deo Reactive Extensions (RxJS) biblioteke koja se koristi za rad sa asinkronim događajima i podacima. Observable predstavlja tok podataka koji možete posmatrati i reagovati na njegove promene. Angular koristi observables za rukovanje asinkronim operacijama kao što su HTTP zahtevi, događaji, promene stanja i mnoge druge situacije gde je asinkrono programiranje od značaja.*)
- da bi posmatrali *Observable* moramo subscribe dodati šta želimo od povratne informacije, u ovom slučaju response želimo dodati useru, u slučaju pogreške želimo izbaciti eror , a uslučaju izvršenja ćemo ispisati poruku za sad poruku"complete"

- međutim kad pokrenemo našu aplikaciju sada dobivamo nazad veliku grešku zbog browserovog security feature jer je nas origin na localhostu 5001 a angular koristi localhost 4200 i da bi tu grešku makli moramo u program.cs - u dodati kurs

![Alt text](<Screenshot 2024-01-01 103435.png>)

Sad smo prespojili podatke s Api-a i da bi vidjeli našu listu Usera i User Id moramo samo ubaciti direktivi *ngFor u naš html na sljedeći način

```ts
<ul>
  <li *ngFor="let user of users">
       {{user.id}} - {{user.userName}}
  </li>
</ul>
```
*Pripaziti na imena u .aspn i na Camel casing jer je jezik osjetljiv na velika slova pogotovo u dijelovima koda koji su u obliku stringa jer nam editor neće izbaciti grešku za isti*

![Alt text](<Screenshot 2024-01-01 105126.png>)

9.Adding Bootstrap and font-awsome 

za instalaciju bootstrapa ćemo koristiti ngx-botstrap od Angulara

[ngx-bootstrap](https://valor-software.com/ngx-bootstrap/#/documentation)
i naredbu `ng add ngx-bootstrap`

te za font-awsome  naredbu `npm install --save @fortawesome/fontawesome-free`

nakon instalacije bootstrapa editor će sam uvesti link u json file dok za font-awsome moramo učiniti to sami

![Alt text](<Screenshot 2024-01-01 112933.png>)

Nakon ovog koraka još moramo instalirati ***mkcert*** certifikat , a da bi njega instalirali treba nam [chocolatey](https://chocolatey.org/) i kada smo sve instalirali stvorimo folder *ssl* damo naredbu `mkcert -install` te nakon nje naredbu `mkcert localhost` da bi dobili key file

- Mkcert je alat koji olakšava postavljanje lokalnog HTTPS-a tijekom razvoja web aplikacija. Omogućava vam generiranje vlastitih lokalnih SSL certifikata za razvojne svrhe, bez potrebe za povjerenjem izdavatelja certifikata (CA). Ovo je korisno kada razvijate web stranice ili aplikacije koje zahtijevaju HTTPS, a želite simulirati sigurno okruženje na lokalnom računalu.

Neki od glavnih razloga za korištenje mkcert uključuju:

Lokalni razvoj s HTTPS-om: Omogućava vam rad s web stranicama koje zahtijevaju HTTPS čak i na lokalnom računalu, što može spriječiti problem s mješavinom sadržaja i omogućava vam simuliranje stvarnih uvjeta rada.

Izbjegavanje sigurnosnih upozorenja preglednika: Kada koristite vlastite lokalne certifikate, možete izbjeći sigurnosna upozorenja preglednika koja se pojavljuju kada radite s nevaljanim certifikatima izdanima od strane nepouzdanih izdavatelja certifikata.

Testiranje sigurnosnih značajki: Omogućava vam testiranje sigurnosnih značajki vaše web aplikacije ili usluge koje zahtijevaju HTTPS.

Mkcert jednostavno pridonosi olakšavanju postavljanja sigurnog lokalnog okruženja za razvoj web aplikacija.

![Alt text](<Screenshot 2024-01-01 132804.png>)

Nakon toga odemo u file angular.json U i pod sekciju "serve" unesemo sljedeće 

![Alt text](<Screenshot 2024-01-01 133414.png>)

Sad kad ponovo pokrenemo aplikaciju neće više biti na http localhost 4200 već na https localhost 4200. Razlika između HTTP (Hypertext Transfer Protocol) i HTTPS (Hypertext Transfer Protocol Secure) leži u načinu prijenosa podataka između web preglednika korisnika i web poslužitelja.









