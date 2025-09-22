## Ordner / Dateien
- ```handle_update.py```: Mein Skript zur Lösung der Aufgabe
- ```run_update_handler.sh```: Skript zum Aktivieren der virtuellen Umgebung, bevor ```handle_update.py``` ausgeführt wird
- ```diun.yml```: Einstellungen für Diun
- ```compose.yml```: Beispiel Docker Compose mit veralteten Versionen von Redis, Nginx und MariaDB zu Demonstrationszwecken
- ```example_reports/```: Die Reports, welche mein Tool auf Basis der o.g. veralteten Container generiert

## Anforderungen
1. [Docker](https://docs.docker.com/desktop/setup/install/linux/)
2. [DIUN](https://crazymax.dev/diun/install/binary/)
3. [Trivy](https://trivy.dev/v0.66/getting-started/installation/)

## Installation
1. ```mv .env.example .env```
2. .env ausfüllen
3. ```uv sync ```

## Bedienung
Um das Tool normal zu benutzen:
1. ```./diun serve --config diun.yml```

Um das Tool anhand der Beispiele in ```compose.yml``` zu testen:
1. ```docker compose up -d```
2. ```./diun serve --config diun.yml```
3. Ctrl+C bzw. ```pkill diun```
4. Kommentare vor ```diun.watch_repo=true```, ```diun.sort_tags=semver```, ```diun.max_tags=1``` in ```compose.yml``` entfernen.
5. ```docker compose up -d```
6. ```./diun serve --config diun.yml```

## Designentscheidungen / Dependencies
1. [DIUN](https://crazymax.dev/diun) zur automatischen Suche nach Updates im Docker Hub. Dieses Tool existiert seit fünf Jahren, wurde in diversen Reddit Threads genannt und von Google als Erstes gefunden. Das [zugehörige GitHub Repo](https://github.com/crazy-max/diun/) hat über 4000 Sterne und wird mehrfach pro Woche geupdatet. Das wirkte auf mich überzeugend. Als Alternative habe ich über [Dockcheck](https://github.com/mag37/dockcheck) und [Watchtower](https://github.com/containrrr/watchtower) nachgedacht, die vermutlich auch beide funktioniert hätten, wobei Watchtower primär darauf ausgelegt zu sein scheint, Updates auch tatsächlich durchzuführen (lässt sich wohl in den Einstellungen via MONITOR_ONLY deaktivieren, aber eine kurze Google-Suche zeigte, dass dies offenbar nicht immer wie gewünscht funktioniert).
2. [Trivy](https://trivy.dev/latest/) zum Auffinden von Sicherheitslücken. Auch hier gab es mehrere Alternativen, aber Trivy wurde mir von Claude als angeblich beste und außerdem leicht bedienbare Option empfohlen, was mir nach weiterer Recherche in etwa richtig vorkam. Da das [GitHub Repo](https://github.com/aquasecurity/trivy) fast 30.000 Sterne hat und regelmäßig geupdatet wird, schien mir Trivy eine solide Option zu sein.
3. [Rich](https://github.com/Textualize/rich) zum Formattieren des Outputs.
4. [Langchain](https://www.langchain.com/) für den AI-Bericht. Da die AI-Integration sich bisher letztlich auf eine ziemlich simple Funktion beschränkt, ist Langchain als Framework eigentlich unnötig umgangreich; jedenfalls hätte die OpenAI SDK locker auch gereicht. Ich habe trotzdem Langchain genommen, um flexibel zu sein, falls das Tool später um zusätzliche GenAI-Funktionen erweitert werden soll.

## Herausforderungen
1. Mangelnde Vertrautheit mit Docker. Ich habe Docker zwar schon benutzt, kannte mich mit den Details der Architektur und Bedienung aber noch nicht aus, und musste mich hier erstmal in diverse Konzepte einlesen.
2. Testen mit DIUN. Da ich keine Kontrolle darüber habe, ob und wann die in der Aufgabe genannten Repos aktualisiert werden, musste ich DIUN dazu bringen, neue Updates zu erkennen, ohne, dass das betreffende Repo tatsächlich aktualisiert worden wäre. Das ging letztlich, hat aber ziemlich viel Herumprobieren erfordert, was sicher auch mit Punkt 1 zusammenhängt.

## Sonstiges
Wie in der Mail schon angemerkt, liegt der Schwerpunkt meiner Lösung eher auf der Interaktion mit Diun und Trivy und dem Aufbereiten der von Trivy gelieferten CVEs. Die AI-Integration ist rudimentär, aber vorhanden. Perspektivisch ließe sich das natürlich beliebig erweitern: Wir könnten z.B. versuchen, das Github Repo und die konkreten Commits zu ermitteln, die dem momentan laufenden und dem neuen Image zugrundeliegen (was allerdings, wenn ich es recht verstehe, nicht ganz einfach wäre, weil es offenbar keinen allgemeingültigen Weg gibt, der diese Zuordnung erlauben würde). Wenn das gelänge, könnten wir die Commit Messages, und womöglich sogar den git diff der beiden commits an die AI schicken, und sie untersuchen lassen, ob das aktualisiserte Image voraussichtlich breaking changes gegenüber unserer momentan genutzten Version beinhaltet. Den finalen Report könnten wir dann um eine Kosten-Nutzen-Analyse anreichern (Aufwand des Updates und Risiko von breaking changes vs. Verbesserung in Bezug auf CVEs). Damit wären wir dann im Bereich von komplexen Analyse- und Abwägungs-Aufgaben, die sich ohne GenAI kaum erledigen lassen.