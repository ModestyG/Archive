# Tangle Archive
Mitt slutprojekt. Jag bestämde mig för att göra min egen version av Tumblr och liknande sidor. Från början hade jag tänkt att det skulle vara ett bokarkiv i stil med AO3 (fast för faktiska böcker) men när jag bytte så orkade jag inte byta namn på alla filer så projektet är nu nicknamat Archive

När du klonar projektet måste du skapa en .env fil där du kan lagra "SECRET_KEY", "RECAPTCHA_PUBLIC_KEY", och "RECAPTCHA_PRIVATE_KEY".

Secret Key väljer du själv men se till att den är svårkäckt.

ReCAPTCHA Keys får du via att gå in på https://www.google.com/recaptcha/admin/create och registrera domänen du vill använda.
Om du hostar localt måste du registrera 127.0.0.1 istället för localhost för att det ska fungera.
