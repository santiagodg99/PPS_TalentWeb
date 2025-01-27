# Correcciones en código Web_Talent-ScoutTech

## Archivo auth.php
Veamos la función **SQLite3::escapeString()**:

```php
$query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = "' . $user . '"');
```

Podemos apreciar que dicha función se aplica a toda la consulta en lugar de solo al parámetro *$user*. Como resultado, las comillas dobles que delimitan el valor del usuario no se eliminan correctamente, lo que permite la inyección de **código SQL malicioso**. 

Para corregir esta vulnerabilidad deberemos cambiar esa línea por las siguientes:

```php
$query = “SELECT userId, password FROM users WHERE username = :username”;

$stmt = $db -> prepare ($query);

$stmt -> bindValue(‘:username‘, $user, SQLITE3_TEXT);
```

Al usar bindValue(), el valor de $user se trata como un dato y no como parte de la consulta SQL. Esto impide que un atacante inyecte código malicioso.

La consulta SQL y los datos se manejan por separado, lo que mejora la claridad y seguridad del código.

En cuanto al apartado de login, deberemos realizar los siguientes cambios:

1.- Usar sesiones en lugar de cookies: Las cookies son vulnerables a ataques de intercepción y manipulación. En cambio, las sesiones almacenan datos en el servidor, lo que es más seguro para información sensible como nombres de usuario y contraseñas.

Para ello podemos escribir el siguiente código:
```php
session_start();
if (isset($_POST['username'])) {
    $_SESSION['user'] = $_POST['username'];
    if(isset($_POST['password'])) {
        $_SESSION['password'] = $_POST['password'];
    }
}
```

2.- Hashear las contraseñas, ya que almacenarlas en texto plano supone una gran vulnerabilidad. Haremos uso del siguiente código:
```php
if(isset($_POST['password'])) {
    $_SESSION['password'] = password_hash($_POST['password'], PASSWORD_DEFAULT);
}
```
3.- Validar y sanitizar todas las entradas de usuario para prevenir ataques de inyección y XSS, a partir del siguiente código:
```php
$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
```

Esta línea de código utiliza la función filter_input() de PHP para obtener y sanitizar el valor del campo 'username' enviado por POST.


## Archivo add_comment.php
Fijémonos en la construcción de la consulta SQL:

```php
$query = "INSERT INTO comments (playerId, userId, body) VALUES ('".$_GET['id']."', '".$_COOKIE['userId']."', '$body')";
```

Aunque $body está escapado, **$_GET['id']** y **$_COOKIE['userId']** se insertan directamente en la consulta sin ningún tipo de escape o validación, lo que permite inyecciones SQL maliciosas.

Para solucionar este problema podemos insertar las siguientes líneas de código:

```php
$stmt = $db -> prepare("INSERT INTO comments (playerId, userId, body) VALUES (?, ?, ?)");

$stmt -> bindValue(1, $_GET['id'], SQLITE3_INTEGER);

$stmt -> bindValue(2, $_COOKIE['userId'], SQLITE3_INTEGER);

$stmt -> bindValue(3, $body, SQLITE3_TEXT);

$stmt -> execute();
```

Estos son nuevamente "prepared statements" que previenen efectivamente las inyecciones SQL al separar los datos de la estructura de la consulta.

## Archivo show_comments.php
Uno de los problemas principales se encuentra en el siguiente trozo de código:
```bash
echo "<div>
    <h4> ". $row['username'] ."</h4> 
    <p>commented: " . $row['body'] . "</p>
</div>";
```
Los datos obtenidos de la base de datos ($row['username'] y $row['body']) se están imprimiendo directamente en el HTML sin ningún tipo de escape o sanitización.

Esto significa que si un atacante logra insertar código JavaScript en estos campos, ese código se ejecutará en el navegador de cualquier usuario que vea la página.

Para solucionarlo podemos sustituir el código de esas líneas por el siguiente:

```bash
echo "<div>
    <h4>" . htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8') . "</h4> 
    <p>commented: " . htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8') . "</p>
</div>";
```

la función htmlspecialchars() permite convertir caracteres especiales en entidades HTML, lo que evitará que se interpreten como código.

## Archivo register.php
Debemos implementar las siguientes medidas:

### Utilizar prepared statements en lugar de SQLite3::escapeString, ya que con ellas se previenen mejor las inyecciones SQL al ofrecer una separación clara entre los datos y la estructura de la consulta. El código a implementar sería el siguiente:

```php
$stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
$stmt->bindValue(':username', $username, SQLITE3_TEXT);
$stmt->bindValue(':password', $password, SQLITE3_TEXT);
$stmt->execute();
```

Este código ofrece las siguientes funcionalidades:
+ Al separar los datos de la estructura de la consulta, se evita que entradas maliciosas manipulen la lógica de la consulta.
+ No es necesario escapar manualmente los datos, ya que el motor de la base de datos lo hace automáticamente.
+ Para consultas repetitivas, las declaraciones preparadas pueden ser más eficientes, ya que la base de datos puede reutilizar el plan de ejecución.
+ Al especificar SQLITE3_TEXT, aseguramos que los datos se traten correctamente como texto en la base de datos.


### Validar y sanitizar las entradas, lo que prevendrá los ataques XSS. El código a implementar sería el siguiente:

```php
$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
if (!$username || strlen($username) < 3 || strlen($username) > 50) {
    die("Invalid username");
}
```

Este código sanitiza la entrada del usuario para el nombre de usuario, y luego verifica que tenga entre 3 y 50 caracteres. Si no cumple con estos criterios, el script se detiene, evitando que se procesen nombres de usuario inválidos.


### Implementar protección contra CSRF para prevenir ataques de falsificación de solicitudes entre sitios. Para ello podríamos escribir el siguiente código:

```php
session_start();
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed");
    }
}
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
```

Este código protege contra CSRF ya que genera un token único para cada sesión, verifica que cada solicitud POST incluya este token, asegura que el token enviado coincida con el almacenado en la sesión y genera un nuevo token después de cada verificación, lo que aumenta la seguridad.


### Implementar una política de contraseñas seguras que obligue a los usuarios a crear contraseñas más robustas, dificultando los ataques de fuerza bruta. Para ello podríamos introducir el siguiente código:
```php
if (strlen($password) < 8 || !preg_match("/[A-Z]/", $password) || !preg_match("/[a-z]/", $password) || !preg_match("/[0-9]/", $password)) {
    die("Password must be at least 8 characters long and contain uppercase, lowercase, and numbers");
}
```

Este código hace que la contraseña deba tener una longitud mínima de 8 caracteres y que incluya mayúsculas, minúsculas y números, lo que ayuda a mejorar su seguridad.

### Hashear las contraseñas para proteger su confidencialidad en caso de que la base de datos se vea comprometida. Para ello podríamos insertar la siguiente línea de código:
```php
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
```

### Implementar un sistema de roles y permisos y verificar la autenticación del usuario en cada página restringida. Para ello podemos introducir el siguiente código:
```php
// Verificar autenticación
function isAuthenticated() {
    return isset($_SESSION['user_id']);
}

// Verificar rol
function hasRole($role) {
    return $_SESSION['user_role'] === $role;
}

// Uso
if (!isAuthenticated()) {
    header('Location: login.php');
    exit();
}

if (!hasRole('admin')) {
    die('Acceso denegado');
}
```
### Usar HTTPS para cifrar la comunicación y regenerar el ID de sesión tras un inicio de sesión exitoso. Para ello introduciremos el siguiente trozo de código:
```php
// Forzar HTTPS
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    $redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header('HTTP/1.1 301 Moved Permanently');
    header('Location: ' . $redirect);
    exit();
}

// Después de un inicio de sesión exitoso
session_start();
if ($login_successful) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user_id; // Asignar el ID de usuario u otra información relevante
}
```
Este código verifica si la conexión es HTTPS y, si no lo es, redirige al usuario a la versión segura del sitio. Además, tras un inicio de sesión exitoso, regenera el ID de sesión para mejorar la seguridad.

### Establecer tiempos de expiración para sesiones inactivas e implementar un mecanismo seguro para cerrar sesión. Podemos hacer todo esto escribiendo el siguiente código:
```php
// Establecer tiempo de expiración
$_SESSION['LAST_ACTIVITY'] = time();

// Verificar expiración
if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > 1800)) {
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit();
}

// Cerrar sesión
session_unset();
session_destroy();
```

Este código asegura que las sesiones inactivas se cierren automáticamente después de 30 minutos y proporciona un método para cerrar sesiones manualmente.



