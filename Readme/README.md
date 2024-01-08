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

9.Making http request in Angular

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
![Alt text][def]

10.Adding Bootstrap and font-awsome

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

[def]: <Screenshot 2024-01-01 105126.png>

11.Uklanjanje hot reloada u terminalu

Da bi promjenili pokretanje aplikacije u hotreload zato jer nam često hotreload daje osječaj da smo pokrenuli aplikaciju sa snimljenim promjenama iako kasnije vidimo da nam nije uključio sve promjene prilikom ponovnog učitavanja. Da bi to učinili pokrenut ćemo našu aplikaciju drugom naredbom u terminalu: `dotnet watch --no-hot-reload`

12.Safe storage of passwords (password hashing & password salting)

Password Hashing i Password Salt su tehnike koje se često koriste u zaštiti lozinki korisnika u sustavima za prijavu. Evo njihovih osnovnih objašnjenja:

Password Hashing (Haširanje lozinke):

Što je to: Kada korisnik postavi lozinku, umjesto da se pohrani ta lozinka, sustav izračunava njezin heš (kriptografski sažetak).
Zašto je to važno: Ako se lozinke čuvaju u obliku čitljivom za ljude, bilo kakvo curenje podataka može dovesti do kompromitiranja korisničkih računa. Haširanje štiti stvarne lozinke od izravnog očitavanja.
Kako se to radi: Korištenjem kriptografskih funkcija za haširanje (npr., bcrypt, scrypt, SHA-256). Ovi algoritmi generiraju "digest" koji je teško rekonstruirati natrag u originalnu lozinku.
Password Salt (Sol za lozinku):

Što je to: Salt je nasumični podatak koji se dodaje originalnoj lozinki prije nego se izračuna heš. Svaki korisnik ima svoj jedinstveni salt.
Zašto je to važno: Dodavanjem soli otežava se "rainbow table" napadi i povećava sigurnost jer iste lozinke dobivaju različite heševe zbog jedinstvenog salta.
Kako se to radi: Prilikom stvaranja korisničkog računa, sustav generira nasumični salt, dodaje ga korisničkoj lozinci, a zatim izračunava heš od kombinacije.
Primjena obje tehnike (haširanje i soljenje) čini lozinke korisnika znatno sigurnijima jer otežava napade na baze podataka i sprječava da se heširane lozinke prepoznaju među korisnicima s istim lozinkama.

Prvo ćemo u entities folderu u API konstruktoru dodati Password Hashing i Password Salt kao byte array

![Alt text](<Screenshot 2024-01-02 092712.png>)

Svaki put kad dodamo nove propertije u entities hoćemo reći našij bazi da mora dodati dvije nove kolumne za ova dva propertia , a to ćemo ostvariti na način da ćemo stvoriti novu migraciju
Moramo stopirati našu aplikaciju svakim dodavanjem migracije i zatim ćemo naredbom `dotnet ef migrations add UserPasswordAdded`

U folderu Migrations vidimo da su naše migracije dodane

![Alt text](<Screenshot 2024-01-02 094246.png>)

Nakon toga ćemo u terminalu dati naredbu `dotnet ef database update` da bi primjenili naše migracije na bazu

![Alt text](<Screenshot 2024-01-02 094634.png>)

u terminalu vidimo da je dodano a ako otvorimo našu tablicu možemo vidjeti da je odrađena migracija

![Alt text](<Screenshot 2024-01-02 094959.png>)

13.Creating a BaseApiController

Da bi naši kontroleri radili svaki bi trebao imati [ApiController] atribut i Route i svaki controller bi trebao biti izveden iz ControllerBase klase. Da bi si uštedili vrijeme na tipkanju ići ćemo u Controller folder i stvorit ćemo new class (novi kontroler) i dati ćemo mu ime BaseApiControler. Izrezati ćemo is UserController atribut i rutu te ćemo ga pasteti u naš novi kontroler. Nakon toga ćemo u UserController-u promjeniti nasljeđivanje iz BaseApiController te možemo izbrisati atribut i routu iz njega. Istu stvsr ćemo ponoviti u našem WeatherForecastControlleru . Nakon toga ćemo u postmanu iskontrolirati sve naše requeste da bi provjerili da nam controlleri rade.Prije postmana pokrenuti našu aplikaciju!

14.Creating an AccountController with register endpoint

Kreirati ćemo ovaj kontroler Account controller da bi useru dali mogućnost registracije. Dati ćemo mu nasljeđivanje iz BaseApiController klase, ali ćemo dodati još jednom DataContext.

```c#
namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
         private readonly DataContext _context;
        public  AccountController(DataContext context)
        {
            _context = context;
        }

        [HttpPost("register")]//api/account/register
        public async Task<ActionResult<AppUser>> Register(string username, string password)
        {
            using var hmac = new HMACSHA512();


            var user = new AppUser
            {
                UserName = username,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password)),
                PasswordSalt = hmac.Key

            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return user;
        }

    }
}
```

Nakon toga ćemo dodati end point ([HttpPost]) u koji ćemo specificirati rutu koja će biti `/api/account/register`

![Alt text](<Screenshot 2024-01-02 173027.png>)

Nakon toga

![Alt text](<Screenshot 2024-01-02 173435.png>)

Koristit ćemo public async metodu a vratit ćemo Task<> od ActionResault i zasada ćemo vratiti AppUsera odnosno metodu Register koja će uzeti dva parametra (username i password)
Password moramo hashirati i saltati ali nećemo sami pisati algoritam jer .net aplikacija koristi klase koje će to uraditi za nas. Klasu koju ćemo koristiti se zove `HMACSHA512`

HMAC-SHA512 (Hash-Based Message Authentication Code with SHA-512) je kriptografski algoritam koji se koristi za generiranje autentikacijskog koda (MAC) pomoću SHA-512 kao kriptografske funkcije za izračunavanje heševa. HMAC-SHA512 pruža autentikaciju i integritet poruka koristeći tajni ključ.

A Salting, u kontekstu sigurnosti podataka, odnosi se na dodavanje nasumičnog podatka (sola) originalnoj poruci ili podatku prije izračunavanja heša. Ova tehnika ima ključnu ulogu u poboljšanju sigurnosti, posebno kod generiranja heševa lozinki.Dodavanje soli čini svaki heš jedinstvenim, čak i za iste početne lozinke. Bez soli, dvije identične lozinke proizveli bi isti heš, što olakšava napade poput "rainbow table" napada.

Inicijalizacija HMAC-SHA512 objekta:

`using var hmac = new HMACSHA512();`

Stvara se novi objekt HMACSHA512 koji će se koristiti za heširanje lozinke.
Ključ (salt) generira se automatski i može se dohvatiti pomoću hmac.Key.

Stvaranje korisničkog objekta AppUser:

```csharp

var user = new AppUser
{
    UserName = username,
    PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password)),
    PasswordSalt = hmac.Key
};
```

*Stvara se novi objekt AppUser.
UserName postavlja se na username vrijednost.
PasswordHash postavlja se na heširanu verziju lozinke pomoću hmac.ComputeHash.
PasswordSalt postavlja se na generirani ključ (salt).*

Dodavanje korisničkog objekta u bazu podataka:

```cs
_context.Users.Add(user);
await _context.SaveChangesAsync();
```

*user objekt se dodaje u kolekciju Users u kontekstu baze podataka _context.
Metoda SaveChangesAsync asinkrono sprema promjene u bazi podataka.*

Vraćanje rezultata akcije:
`return user;`

*Kada korisnik uspješno registrira svoj račun, vraća se objekt AppUser kao rezultat akcije.*

![Alt text](<Screenshot 2024-01-02 182857.png>)

*using blok koristi se za inicijalizaciju i upravljanje resursima za HMACSHA512 objekt. Kada se using blok završi, automatski će biti pozvana Dispose metoda na HMACSHA512 objektu, što osigurava pravilno oslobađanje(brisanje) resursa. Ovo se često koristi za resurse koji implementiraju IDisposable, kao što su objekti za kriptografske operacije.*

15.Using DTO

DTO, ili Data Transfer Object, je oblik oblikovanja podataka koji se koristi za prijenos podataka između različitih slojeva ili komponenti sustava, obično između poslužiteljskog sloja (server) i klijentskog sloja (client) ili između različitih dijelova istog sustava. Cilj DTO-a je prenositi podatke sa što manje informacija o njihovom izvoru ili načinu pohrane, čime se povećava modularnost sustava i smanjuje ovisnost između različitih dijelova aplikacije.

Ključne karakteristike DTO-a:

Prenos Podataka:

DTO služi za prenošenje podataka između različitih dijelova sustava. To može uključivati podatke koji se prenose od poslužitelja prema klijentu ili između različitih servisa unutar iste aplikacije.
Minimaliziranje Informacija:

DTO obično sadrži samo podatke koji su potrebni u određenom kontekstu. To može značiti da se preskaču određene informacije koje su bitne samo u izvornom dijelu sustava.
Razdvajanje Slojeva:

Koristi se za odvajanje različitih slojeva arhitekture aplikacije kako bi se smanjila ovisnost i omogućila lakša promjena u jednom dijelu sustava bez utjecaja na druge dijelove.

Kada pokušamo pokrenuti aplikaciju kroz Postman alat ukazuje nam na neke greške:

![Alt text](<Screenshot 2024-01-02 190836.png>)
![Alt text](<Screenshot 2024-01-02 191043.png>)

Obično naš kompiler automatski udružuje kontroler argumentima unutar funkcija , ali ne i u ovom slučaju. U našoj metodi AppUser funkcija GetBytes očekuje string s a mi mu šaljemo parametar password koji ne prolazi kroz našu metodu zato jer u našoj Register metodi nezna gdje da traži password iako ga šaljemo kao argument mi u biti šaljemo objekt
![Alt text](<Screenshot 2024-01-02 192801.png>)

a unutar našeg Register imamo dva parametra koji su stringovi.

Unutar našeg Api foldera ćemo kreirati novi folder DTOs i u njemu ćemo otvoriti novu klasu RegisterDto unutar koje ćemo navesti dva propertia koje želimo primiti prilikom kreiranja novog objekta. DTO je u biti objekt koji spremi neke podatke i iz jednog subsistema šalje te podatke u drugi sub sistem , ali samo podatke koje mi odredimo da želimo poslati što u našem slučaju nije da želimo poslati paswordHash i paswordSalt već isključivo ime i pasword.

![Alt text](<Screenshot 2024-01-03 111943.png>)

a zatim ćemo u naše Register metodu dodati neke promjene:

1. prvo ćemo kreirati u našem AccountControlleru jednu async metodu  UserExist koja će vršiti provjeru dali user name već postoji

2. zatim ćemo je pozvati odmah prije instanciranja HMAC-a i promjenit ćemo parametre metode Registar

3. obratit ćemo pozornost na mala i velika slova i druge parametre koje još treba izmjeniti

![Alt text](<Screenshot 2024-01-03 112726.png>)

16.Adding validation

```c#

using System.ComponentModel.DataAnnotations;

namespace API.DTOs
{
    public class RegisterDto
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
```

- dovoljno je da validaciju unesemo u naš RegisterDto pomoću atributa [Required] zato jer naš BaseApiController ima već atribut [ApiController] koji omogućava da prenese podatak..

![Alt text](<Screenshot 2024-01-03 122641.png>)

Kad pokrenemo debuger i u Postmanu pokušamo dodati novog usera i ako ostavimo ime prazno ukazat će korisniku da Ime mora biti ispunjeno
![Alt text](<Screenshot 2024-01-03 123256.png>)

17.Adding login endpoint

Sljedeći korak je da klientu(user) kad je poslao ime i password nakon provjere imena i passworda damo odgovarajuću povratnu informaciju. To još ne znači da se je logirao jer kad naš api server i client server u ovom kontekstu naš klient ne ostvaruje nikakvu sesiju sa našim api serverom. Ne postoji nikakvo stanje već je naš api konstruiran bez stanja tako da primi request napravi logiku koji taj request traži i vrati response.
Ispod našeg httpPost - register ćemo dodati httpPost - login

1.Kreirati ćemo klasu LoginDto koja će imati iste propertie kao i RegisterDto ali ćemo ipak napraviti odvojenu klasu jer ćemo kasnije dodavati još neke akcije na RegisterDto:

```c#
namespace API.DTOs
{
    public class LoginDto
    {
        public string Username { get; set; }
        public string  Password { get; set; }
    }
}
```

2.Kad se ulogira klient prvo će nam trebati user član kojem ćemo prim jeniti metodu SingleOrDefault.
*SingleOrDefault:Vraća jedini element iz sekvence koji zadovoljava uslov ili podrazumevanu vrednost ako nijedan element ne zadovoljava uslov.
Ako sekvence ima više od jednog elementa, ili je prazna, baca izuzetak InvalidOperationException.
Koristi se kada očekujete tačno jedan rezultat i želite izuzetak ako se to pravilo prekrši.*
U zagradi ćemo proslijediti što želimo naći `(x => x.UserName == loginDto.Username)`

3.Da se user nebi ulogirao s krivim imenom moramo provjeriti sa if statment ako user ne postoji u našoj bazi vratit ćemo Unautorized ("Invalid username")

4.nakon što smo provjerili usera moramo provjeriti password

5.Sad imamo dva niza bytova koje trebamo usporediti dali se podudaraju da bi mogli proći autorizaciju

![Alt text](<Screenshot 2024-01-03 134717.png>)

18.Adding a token service

JSON Web Token (JWT) je standard za prenos claims (tvrdnji) između dve strane u formatu koji je bezbedan i kompaktan, često korišćen u autentikaciji i autorizaciji procesa na webu. JWT se sastoji od tri delimična deo, odvojenih tačkom ("."). Ovi delovi su:

Header (Zaglavlje):

JSON objekat koji sadrži informacije o tipu tokena ("typ") i algoritmu koji se koristi za potpisivanje tokena ("alg").
Primer zaglavlja:
json

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Payload (Sadržaj):

JSON objekat koji sadrži tvrdnje (claims). Tvrdnje mogu biti informacije o korisniku, dozvolama ili druge podatke.
Primer sadržaja:
json

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "exp": 1516239022
}
```

Standardne tvrdnje uključuju sub (subject), iss (issuer), exp (expiration time), i mnoge druge.
Signature (Potpis):

Potpis se kreira od kombinacije zaglavlja, sadržaja i tajnog ključa koristeći određeni algoritam koji je naveden u zaglavlju.
Primer potpisa (potpisan uz pomoć HMAC SHA-256 algoritma):
scss

```scss

HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

JWT se često koristi u autentikaciji. Kada korisnik uspešno izvrši prijavljivanje (login), server generiše JWT koji sadrži informacije o korisniku i šalje ga korisniku. Korisnik zatim uključuje taj JWT u svaki zahtev prema serveru, omogućavajući serveru da proveri identitet korisnika i odobri pristup resursima. Budući da je JWT potpisan, server može proveriti da li je neko drugi promenio sadržaj tokena.

Sad imamo metode za register i login i trebali bi ubaciti token, i kreirat ćemo service koji će to odraditi

1.Ako pogledamo u program.cs za sada smo dodavali servise koji su već u Entitiy Frameworku, a ovog puta ćemo sami stvoriti svoj service i dodati ga u nač service kontejner u program.cs klasi tako da bi mogli inicirati naš vlastiti servis u controller ili u accountController tako da kad se user logira možemo mu pružiti token koji će mu pružiti servis koji ćemo kreirati.Kad kreiramo servis ćemo u biti kreirati interface koji će reć implementaciji koje metode podržava.

2.U API folderu ćemo kreirati novi folder Interfaces i unutar njega novi interface koji ćemo nazvati ITokenService

![Alt text](<Screenshot 2024-01-03 152141.png>)

  IToken Service će sadržavati jednu metodu:

  ```c#
  using API.Entities;

namespace API.Interfaces
{
    public interface ITokenService
    {
        string CreateToken(AppUser user);
    }
}
  ```

*ovaj interface služi kao contract(ugovor) svaka klasa koja implementira ovaj interface mora podržavati ovu metodu

3.Nakon toga ćemo kreirati novi folder unutar API i nazvat ćemo ga services i unutar njega NewC# klasu TokenService koja će nasljediti ITokenService i koja po ugovoru mora implementirati jedinu metodu koju naš interface sadrži CreateToken koju možemo ubaciti pomoću quickfix:

```c#

public string CreateToken(AppUser user)
{
    throw new NotImplementedException();
}
```

3.Nakon toga ćemo dodati u program.cs klasi naš service:

`builder.Services.AddScoped<ITokenService, TokenServices>();`

*AddScoped metoda je deo IServiceCollection objekta koji predstavlja DI kontejner i koristi se za registraciju servisa u okviru tog kontejnera.*

builder.Services: Ovo se odnosi na IServiceCollection objekt, koji predstavlja kontejner za Dependency Injection.

AddScoped<ITokenService, TokenServices>(): Ova metoda registruje servis u DI kontejneru. Evo šta svaki deo znači:

ITokenService: Ovo je interfejs koji predstavlja kontrakt za funkcionalnosti vezane za rad sa tokenima.

TokenServices: Ovo je konkretna implementacija interfejsa ITokenService. Kada aplikacija zatraži ITokenService, DI kontejner će pružiti instancu TokenServices. Ova instanca će biti kreirana jednom po zahtevu (scoped lifetime), što znači da će biti dostupna tokom celog trajanja jednog HTTP zahteva, a zatim će biti uništena

19.Adding the create token logic

Za početak ćemo skinuti jedan extension koji se zove System.IdentityModel.Tokens.Jwt. Biblioteka koja omogućuje .NET aplikacijama generiranje i verifikaciju JWT tokena.
Sadrži klase za rad s JWT zaglavljima, tijelom, potpisom te alatima za generiranje i analizu JWT tokena.

```c#
  public class TokenServices : ITokenService
    {
        private readonly SymmetricSecurityKey _key;//pohrana private polja koju dobivamo iz using Microsoft.IdentityModel.Tokens;
        public TokenServices(IConfiguration config)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));//postavljanje ključa
        }

```

Prvo ćemo kreirati konstrukror dodati mu IConfiguration i u njemu ćemo pohraniti naš tajni ključ.
SymmetricSecurityKey se koristi kada isti ključ koristi za šifrovanje i dešifrovanje podataka. Ovaj tip ključa je simetričan, što znači da isti ključ koristi za oba procesa. To se razlikuje od asymetričnog šifrovanja gde postoje odvojeni ključevi za šifrovanje i dešifrovanje.

```c#

  public string CreateToken(AppUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.NameId,user.UserName)
            };
            var creds = new SigningCredentials(_key,SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject= new ClaimsIdentity(claims),
                Expires= DateTime.Now.AddDays(7),
                SigningCredentials=creds
            };
            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
```

*U ovom kontekstu, funkcija CreateToken se obično koristi prilikom uspešne autentikacije korisnika kako bi se generisao JWT token koji se zatim može poslati korisniku. Taj token može biti upotrebljen za autorizaciju korisnika pri pristupu resursima na serveru. Važno je primetiti da treba pažljivo upravljati ključem (_key), jer je on ključni deo sigurnosti JWT tokena.*

Inicijalizacija podataka (claims): Kreiraju se tvrdnje (claims) koje će biti uključene u JWT token. U ovom primeru, dodaje se tvrdnja o korisničkom imenu (JwtRegisteredClaimNames.NameId) koja će sadržati vrednost korisničkog imena iz objekta user.

Postavljanje potpisa (creds): Koristi se simetrični ključ _key (verovatno tipa SymmetricSecurityKey) i odabrani algoritam potpisa (SecurityAlgorithms.HmacSha512Signature) kako bi se kreirao objekat SigningCredentials. Ovaj potpis će se koristiti za potpisivanje JWT tokena.

Konfiguracija tokena (tokenDescriptor): Postavljaju se osnovne informacije o JWT tokenu, uključujući tvrdnje, vreme isteka tokena (Expires), i potrebne potpisne informacije (SigningCredentials).

Generisanje tokena (tokenHandler): Kreira se instanca JwtSecurityTokenHandler, a zatim se koristi da stvori JWT token koristeći informacije iz tokenDescriptor.JwtSecurityTokenHandler je klasa koja se koristi za manipulaciju i rad sa JSON Web Token (JWT) objektima u .NET okviru. Ova klasa dolazi iz System.IdentityModel.Tokens.Jwt namespace-a i pruža funkcionalnosti za stvaranje, čitanje i validaciju JWT tokena.

Povratna vrednost: Generisani JWT token se zatim vraća kao string pomoću tokenHandler.WriteToken(token).

20.Creating a User DTO and returning the token

Sad kad imamo logiku za token da bi vratili token kad se naš user registrira trebamo napraviti sljedeće. Treba nam nova DTO klasa koja će nam ovaj puta vraćati string Username i string tokena.

```c#

public class UserDTO
    {
        public string Username { get; set; }
        public string Token { get; set; }
    }
```

U Account controller ćemo dodati interface ITokenService i upotrijebit ćemo *Initialize field from parametar* (označimo ga i pogledamo show fixes)

![Alt text](<Screenshot 2024-01-08 125237.png>)

Zatim mjenjamo umjesto da vraćamo AppUser vraćamo UserDto i  return user mjenjamo u return new userDto
 ![Alt text](<Screenshot 2024-01-08 130034.png>)
I istu stvar ponovimo u našoj login metodi
![Alt text](<Screenshot 2024-01-08 130307-1.png>)

Nakon toga  unutar naše TokenService klase imamo config key koji je namješten na TokenKey i moramo ga dodati  u konfiguraciju

![Alt text](<Screenshot 2024-01-08 130744.png>)

Inače bi taj ključ stavili u apsettings.json ali za potrebe developmenta ćemo ga dodati u appsettings.Development.json da bi nam bilo lakše razumijeti

![Alt text](<Screenshot 2024-01-08 131032.png>)
*imajmo na umu da će nam u stvarnom svijetu trebati jaki ključ za tokenKey koji nam sad u development modu nije tako važan*

Ako nakon ovoga odemo u postman i pošaljemo request za jednog usera da nam vrati za test naš token koji ćemo kopirati te na stranici [jwt.ms](https://jwt.ms/). testirati i vidimo da je naš user jovo dobio novi token kojim se ulogirao u našu aplikaciju

![Alt text](<Screenshot 2024-01-08 131807.png>)

![Alt text](<Screenshot 2024-01-08 131848.png>)

21.Adding the authentication middleware

Da bi dodali autentifikaciju u našu aplikaciju odnosno da bi primjenili već dodanu autentifikaciju trebamo dodati midlewere. Middleware (srednje slojevi) u kontekstu web aplikacija, uključujući ASP.NET Core, predstavlja skup komponenti koje se izvršavaju između zahteva klijenta i odgovora servera. Srednji slojevi su deo HTTP zahteva i odgovora pipeline-a i omogućavaju vam da dodate funkcionalnosti i logiku na nivou zahteva ili odgovora.

Prvo ćemo otići u nas user controller i dodati atribut [Authorize]
![Alt text](<Screenshot 2024-01-08 172756.png>)

Prilikom dodavanja atributa moramo imati na umu sljedeće pravilo
![Alt text](<Screenshot 2024-01-08 132707.png>)

Nakon toga trebamo dodati services u kalasi Program.cs , a prije toga nam je potreban jedan extension iz NuGet Gallery koji se zove Microsoft.AspNetCore.Authentication.JwtBearer

![Alt text](<Screenshot 2024-01-08 173523.png>)

zatim dodamo service čija pozicija unutar program.cs nije krucijalna:

![Alt text](<Screenshot 2024-01-08 173245.png>)

i nakon toga dodati prvo app.UseAuthentiaction zatim app.UseAuthorization

![Alt text](<Screenshot 2024-01-08 174125.png>)

22.Adding extension methods

Nakon što smo sredili sve malo ćemo porediti stvari na način da ćemo odvojiti iz program.cs neke servise da nam nebi bila takva gužva u jednoj klasi te da bi nam kod izgledao čišće i urednije

Otići ćemo u klasu program.cs te ćemo izrezati dio koda koji nam služi za dbContekst , zatim ćemo otvoriti novi folder Extensions te u njemu kreirati prvo klasu ApplicationServiceExtensions u koju ćemo prebaciti servis za db kontekst, a kad unutar klase naljepimo service moramo ga malo doraditi :

```c#
builder.Services.AddDbContext<DataContext>(opt =>
{
    opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));

});
builder.Services.AddCors();
builder.Services.AddScoped<ITokenService, TokenServices>();
```

![Alt text](<Screenshot 2024-01-08 182505.png>)

nakon toga ćemo istu stvar napraviti za Identity service tako što ćemo u extensions folderu otvoriti klasu IdentityServiceExtension te u nju pohraniti service za token iz program.cs i prilagoditi ga novoj klasi

```c#
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(opt =>
{
    opt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding
        .UTF8.GetBytes(builder.Configuration["TokenKey"])),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});
```

![Alt text](<Screenshot 2024-01-08 183544.png>)

na kraju još nam preostaje da u program.cs uvezemo nove extenzije :
![Alt text](<Screenshot 2024-01-08 183152.png>)
