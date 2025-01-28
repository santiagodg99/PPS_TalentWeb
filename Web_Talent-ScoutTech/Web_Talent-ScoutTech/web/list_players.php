<?php
            require_once dirname(__FILE__) . '/private/conf.php';

            # Require logged users
            require dirname(__FILE__) . '/private/auth.php';
            ?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Players list</title>
</head>
<body>
    <header class="listado">
        <h1>Players list</h1>
    </header>
    <main class="listado">
        <section>
            <ul>
            <?php
            #require_once dirname(__FILE__) . '/private/conf.php';

            # Require logged users
            #require dirname(__FILE__) . '/private/auth.php';

            $query = "SELECT playerid, name, team FROM players order by playerId desc";

            $result = $db->query($query) or die("Invalid query");

            while ($row = $result->fetchArray()) {
                echo "
                    <li>
                    <div>
                    <span>Name: " . $row['name']
                 . "</span><span>Team: " . $row['team']
                 . "</span></div>
                    <div>
                    <a href=\"show_comments.php?id=".$row['playerid']."\">(show/add comments)</a> 
                    <a href=\"insert_player.php?id=".$row['playerid']."\">(edit player)</a>
                    </div>
                    </li>\n";
            }

            ?>
            </ul>
            <form action="#" method="post" class="menu-form">
                <a href="index.php">Back to home</a>
                <input type="submit" name="Logout" value="Logout" class="logout">
            </form>
        </section>
    </main>
    <footer class="listado">
        <img src="images/logo-iesra-cadiz-color-blanco.png">
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
</body>
</html>