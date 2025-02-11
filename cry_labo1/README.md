1. Quel est l’avantage d’utiliser le test du χ2 plutôt que de comparer simplement la lettre la plus fréquente dans le texte chiffré par rapport aux statistiques du langage de base? 

Cela nous permet d'avoir une vision ensemble du trend global du text. On peut avoir deux langues qui utilise fréquement une lettre et là ça vaudrait plus rien.

---
2. Pourquoi est-ce que le test du χ2 ne fonctionne-t-il pas directement sur un texte chiffré à l’aide du chiffre de Vigenère?

Vu que le Vigenère utilise pas le même shift pour chaque lettre. Cela rend le chiffre de Vigenère nettement plus résistant à l'analyse des fréquences contrairement à Caesear. Pour la même lettre, il peut avoir plusieurs sortis.

---
3.  Que mesure l’indice de coïncidence?

L'indice de coïncidence calcule la probabilité que deux lettres choisies au hasard dans un texte. Cette mesure permet d'évaluer dans quelle mesure le texte suit une distribution de lettres aléatoire ou correspond à une structure de langue naturelle. En analysant cette probabilité, et en segmentant le texte chiffré en sous-groupes basés sur différentes longueurs de clé supposées, on peut utiliser l'indice de coïncidence pour s'approcher de la longueur réelle de la clé Vigenère. Cela repose sur l'idée que pour la bonne longueur de clé, les sous-groupes refléteront une distribution des lettres plus similaire à celle d'une langue naturelle.

---
4.  Pourquoi est-ce que l’indice de coïncidence n’est-il pas modifié lorsque l’on applique le chiffre de César généralisé sur un texte? 

Vu que le chiffrement de César c'est basé sur un shift les lettre en clair auront répresentation dans le text chiffre. Donc relativement, ça ne change pas les fréquences général d'un text.

---   
5.  Est-il possible de coder un logiciel permettant de décrypter un document chiffré avec le chiffre de Vigenère et une clef ayant la même taille que le texte clair? Justifiez. 

 Non, on n'a pas de pattern cyclique pour qu'on puisse analyser. De plus ça s'approche du concept de one time pad (si la clef était utilisé une fois et que c'était tiré aléatoirement), donc pour bruteforce c'est très complexe...

---   
6.  Expliquez votre attaque sur la version améliorée du chiffre de Vigenère.

Pour chaque combinaison de longueur de clé et de décalage, on découpe le texte en morceaux de la taille de la clé et on décale chaque morceau en utilisant le chiffre de César avec le décalage courant. Le résultat est une version du texte où chaque morceau a été décalé individuellement.  

Ensuite, on calcule l'indice de coïncidence pour chaque morceau décalé et ainsi on calcule la moyenne de ces indices de coïncidence. La raison de prendre la moyenne est d'obtenir une mesure globale de l'indice de coïncidence pour l'ensemble du texte.

Enfin, on compare l'IC moyen à l'IC de référence. Si la différence absolue entre l'IC moyen et l'IC de référence est plus petite que la plus petite différence trouvée jusqu'à présent, on met à jour la plus petite différence et on stocke la longueur de clé et le décalage courants

À la fin, nous avons nos valeurs supposées, et donc nous appliquons notre système pour trouver la valeur de la clé de Vigenère. Après on applique les clés dans la fonction decrypt avec nos clefs retrouvées.


---    
7.  Trouvez une méthode statistique (proche de ce qu’on a vu dans ce labo) permettant de distinguer un texte en anglais d’un texte en français. Qu’en pensez-vous? Testez votre méthode.

Pour les textes plus courts, l'utilisation de l'indice de coïncidence ne fonctionne pas très bien, car la précision est très fine. En ce qui concerne la méthode du chi-carré (X²), on arrive plus ou moins à distinguer les textes en anglais et en français. Cependant, il manque des tests plus robustes. On pourrait peut-être combiner les deux méthodes pour être potentiellement plus précis, mais je pense qu'il faudrait utiliser d'autres méthodes telles que le pattern matching sur les syllabes et les occurrences d'autres caractéristiques des deux langues (Par exemple simplement les accents, ça n'existe pas en anglais).